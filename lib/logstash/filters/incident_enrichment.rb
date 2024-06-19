# encoding: utf-8

require 'logstash/filters/base'
require 'logstash/namespace'
require 'json'
require 'time'
require 'dalli'
require 'securerandom'

require_relative 'util/incident_enrichment_constant'
require_relative 'util/memcached_config'
require_relative 'util/configuration'

module Configuration
  class << self
    attr_accessor :config
  end
end

class LogStash::Filters::IncidentEnrichment < LogStash::Filters::Base
  include MobilityConstant

  config_name "incident_enrichment"

  config :cache_expiration,               :validate => :number, :default => 300,    :required => false # seconds (4 min)
  config :memcached_server,               :validate => :string, :default => "",     :required => false
  config :incident_fields,                :validate => :array,  :default => [],     :required => true

  public
  def register
    @logger.info("[incident-enrichment] Registering logstash-filter-incident-enrichmnet")
    @config.each{ |key, value| Configuration.set_config("#{key}", value) }

    @memcached_server = MemcachedConfig::servers if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0, :value_max_bytes => 4000000})
  end

  def get_score(field)
    field_scores = {
      "lan_ip" => 100,
      "src_ip" => 100,
      "wan_ip" => 100,
      "dst_ip" => 100,
      "lan_port" => 30,
      "wan_port" => 30,
      "src_port" => 30,
      "dst_port" => 30
    }
  
    field_scores.fetch(field, 0)
  end

  def field_prefix(field)
    field_map = {
      "lan_ip" => "ip",
      "src_ip" => "ip",
      "wan_ip" => "ip",
      "dst_ip" => "ip",
      "lan_port" => "port",
      "wan_port" => "port",
      "src_port" => "port",
      "dst_port" => "port"
    }
    field_map.fetch(field, "")
  end

  def save_fields(fields, incident_uuid, key_prefix)
    fields.each do |f|
      key = key_prefix + "_" + field_prefix(f) + "_" + f
      @memcached.set(key, incident_uuid, @cache_expiration)
    end
  end

  def refresh_fields(fields, incident_uuid, key_prefix)
    fields.each do |f|
      key = key_prefix + "_" + field_prefix(f) + "_" + f
      incident_uuid = @memcached.get(key)
      
      next unless incident_uuid

      @memached.set(key, incident_uuid, @cache_expiration)
    end
  end

  def make_incident_relation(fields, incident_uuid, key_prefix)
    return unless fields && !fields.empty?

    partners = []

    fields.each do |f|
      key = key_prefix + "_" + field_prefix(f) + "_" + f

      partner_incident_uuid = @memcached.get(key)
      
      next unless partner_incident_uuid
      partners.push(partner_incident_uuid)
    end

    # Linking only with one incident is ok.. we dont need
    # to link with all as this is a chain
    partner_uuid = partners.first
    relation_key = key_prefix + "_relation_" + incident_uuid
    @memached.set(relation_key, partner_uuid)
  end

  def get_fields_scores(event, key_prefix)
    fields_scores = {}

    incident_fields.each do |f|
      field = event.get(f).to_s
      next unless field

      # rbincident-<namespace_uuid>-<type>-<field-value>
      key = key_prefix + "_" + field_prefix(f) + "_" + field
      cache_key = @memcached.get(key)
      
      next unless cache_key
      
      score = get_score(f)
      fields_scores[f] = score
    end

    fields_scores
  end

  def filter(event)
    namespace = event.get(NAMESPACE_UUID) || ""
    # rbincident-<namespace_uuid> (for now)
    key_prefix = "rbincident_" + namespace

    severity = (event.get(SEVERITY) || "low").downcase

    fields_score = get_fields_scores(event, key_prefix)
    
    score = 0
    fields_score.each { |k, v| score += v }

    # Make a new incident
    if score == 0 && (severity == "high" || severity == "critical")
      incident_uuid = SecureRandom.uuid
      save_fields(incident_fields, incident_uuid, key_prefix)
    end

    # Related incident
    if score > 0 && score < 100 && (severity == "high" || severity == "critical")
      incident_uuid = SecureRandom.uuid

      fields_to_save = []
      fields_score.each { |k,v| fields_to_save.push(k) if v > 0 }
      save_fields(fields_to_save, incident_uuid, key_prefix)

      fields_to_refresh = fields_score - fields_to_save
      refresh_fields(fields_to_refresh, incident_uuid, key_prefix)
      
      make_incident_relation(fields_to_refresh, incident_uuid, key_prefix)
    end

    # Match an existing incident
    if score >= 100
      field_with_max_score = fields_score.max_by { |key, value| value }[0]

      value = event.get(field_with_max_score)
      key = key_prefix + "_" + field_prefix(f) + "_" + value
      incident_uuid = @memcached.get(key)

      fields_to_save = []
      fields_score.each { |k,v| fields_to_save.push(k) if v <= 0 }

      if incident_uuid
        save_fields(fields_to_save, incident_uuid, key_prefix)
      end      
    end

    if incident_uuid
      event.set("incident_uuid", incident_uuid)
    end

    events.each{|e| yield e }
    event.cancel
  end # def filter
end # class Logstash::Filter::Mobility
