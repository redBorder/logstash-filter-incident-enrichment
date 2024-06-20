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
  include IncidentEnrichmentConstant

  config_name "incident_enrichment"

  config :cache_expiration,               :validate => :number, :default => 600,    :required => false # seconds (10 min)
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
      "src" => 100,
      "wan_ip" => 100,
      "dst" => 100,
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
      "src" => "ip",
      "wan_ip" => "ip",
      "dst_ip" => "ip",
      "dst" => "ip",
      "lan_port" => "port",
      "wan_port" => "port",
      "src_port" => "port",
      "dst_port" => "port"
    }
    field_map.fetch(field, "")
  end

  def save_fields(fields, incident_uuid, key_prefix, event)
    fields.each do |f|
      value = event.get(f)
      return unless value

      key = key_prefix + "_" + field_prefix(f) + "_" + value.to_s
      @memcached.set(key, incident_uuid, @cache_expiration)
    end
  end

  def update_fields_time(fields, incident_uuid, key_prefix, event)
    fields.each do |f|
      value = event.get(f)
      return unless value

      key = key_prefix + "_" + field_prefix(f) + "_" + value.to_s
      incident_uuid = @memcached.get(key)
      
      next unless incident_uuid

      @memcached.delete(key)
      @memcached.set(key, incident_uuid, @cache_expiration)
    end
  end

  def save_incident_relation(fields, incident_uuid, key_prefix, event)
    return unless fields && !fields.empty?

    partners = []

    fields.each do |f|
      value = event.get(f)
      return unless value

      key = key_prefix + "_" + field_prefix(f) + "_" + value.to_s

      partner_incident_uuid = @memcached.get(key)
      next unless partner_incident_uuid

      partners.push(partner_incident_uuid)
    end

    # Linking only with one incident is ok.. we dont need
    # to link with all as this is a chain
    partner_uuid = partners.first
    relation_key = key_prefix + "_relation_" + incident_uuid
    @memcached.set(relation_key, partner_uuid)
  end

  def get_fields_scores(event, key_prefix)
    fields_scores = {}

    @incident_fields.each do |f|
      value = event.get(f)
      next unless value

      # rbincident-<namespace_uuid>-<type>-<field-value>
      key = key_prefix + "_" + field_prefix(f) + "_" + value.to_s
      cache_key = @memcached.get(key)
      
      next unless cache_key
      
      score = get_score(f)
      fields_scores[f] = score
    end

    fields_scores
  end

  def get_severity(event)
    severity = event.get(SEVERITY)
    return severity.downcase if severity

    severity = event.get(PRIORITY)
    return severity.downcase if severity

    "low"
  end

  def get_incident_name(event, incident_uuid)
    name = event.get(MSG)

    return name if name

    "Unknow incident name: #{incident_uuid}"
  end

  def save_incident_name(key_prefix, incident_name, incident_uuid)
    return false unless incident_name

    name_key = key_prefix + "_name_" + incident_uuid
    @memcached.set(name_key, incident_name)

    true
  end

  def filter(event)
    namespace = event.get(NAMESPACE_UUID) || ""
    # rbincident-<namespace_uuid> (for now)
    key_prefix = "rbincident_" + namespace

    @memcached.set(key_prefix + "pepe_was_here",nil,300)

    severity = get_severity(event)
    
    fields_score = get_fields_scores(event, key_prefix)
    
    score = 0
    fields_score.each { |k, v| score += v }

    # Make a new incident
    if score == 0 && (severity == "high" || severity == "critical")
      incident_uuid = SecureRandom.uuid
      incident_name = get_incident_name(event, incident_uuid)
      save_incident_name(key_prefix, incident_name, incident_uuid)

      save_fields(@incident_fields, incident_uuid, key_prefix, event)
    end

    # Related incident
    if score > 0 && score < 100 && (severity == "high" || severity == "critical")
      incident_uuid = SecureRandom.uuid
      incident_name = get_incident_name(event, incident_uuid)
      save_incident_name(key_prefix, incident_name, incident_uuid)

      fields_to_save = []
      fields_score.each { |k,v| fields_to_save.push(k) if v <= 0 }
      save_fields(fields_to_save, incident_uuid, key_prefix, event)

      fields_to_update = fields_score.keys - fields_to_save
      update_fields_time(fields_to_update, incident_uuid, key_prefix, event)
     
      save_incident_relation(fields_to_update, incident_uuid, key_prefix, event)
    end

    # Match an existing incident
    if score >= 100
      field_with_max_score = fields_score.max_by { |key, value| value }[0]

      value = event.get(field_with_max_score)
      key = key_prefix + "_" + field_prefix(field_with_max_score) + "_" + value.to_s
      incident_uuid = @memcached.get(key)

      fields_to_save = []
      fields_score.each { |k,v| fields_to_save.push(k) if v <= 0 }

      if incident_uuid
        save_fields(fields_to_save, incident_uuid, key_prefix, event)
      end      
    end

    if incident_uuid
      event.set("incident_uuid", incident_uuid)
    end

    filter_matched(event)
  end # def filter
end # class Logstash::Filter::Mobility
