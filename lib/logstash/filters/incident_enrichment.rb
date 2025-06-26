# encoding: utf-8

require 'logstash/filters/base'
require 'logstash/namespace'
require 'json'
require 'time'
require 'dalli'
require 'securerandom'

require_relative 'util/incident_enrichment_constant'
require_relative 'util/memcached_config'

class LogStash::Filters::IncidentEnrichment < LogStash::Filters::Base
  include IncidentEnrichmentConstant

  config_name "incident_enrichment"

  config :cache_expiration,          :validate => :number, :default => 600, :required => false
  config :memcached_server,          :validate => :string, :default => "", :required => false
  config :incident_fields,           :validate => :array,  :default => [], :required => true
  config :source,                    :validate => :string, :required => true
  config :field_scores,              :validate => :hash,   :default => {}, :required => false
  config :field_map,                 :validate => :hash,   :default => {}, :required => false
  config :incidents_priority_filter, :validate => :string, :default => "high", :required => false

  def register
    @logger.info("[incident-enrichment] Registering logstash-filter-incident-enrichment")

    @memcached_server = MemcachedConfig.servers if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, expires_in: 0, value_max_bytes: 4_000_000, serializer: JSON)

    # Valores predeterminados si no se configuran
    @default_field_scores = {
      "lan_ip" => 100, "src_ip" => 100, "src" => 100, "wan_ip" => 100,
      "dst" => 100, "dst_ip" => 100, "lan_port" => 30, "wan_port" => 30,
      "src_port" => 30, "dst_port" => 30
    }
    @default_field_map = {
      "lan_ip" => "ip", "src_ip" => "ip", "src" => "ip", "wan_ip" => "ip",
      "dst_ip" => "ip", "dst" => "ip", "lan_port" => "port", "wan_port" => "port",
      "src_port" => "port", "dst_port" => "port"
    }

    @field_scores = @field_scores.empty? ? @default_field_scores : @field_scores
    @field_map = @field_map.empty? ? @default_field_map : @field_map

  rescue StandardError => e
    @logger.error("Failed to initialize memcached: #{e.message}")
  end

  def get_score(field)
    @field_scores.fetch(field, 0)
  end

  def field_prefix(field)
    @field_map.fetch(field, "")
  end

  def get_cache_key_name(prefix, field, value)
    "#{prefix}:#{field_prefix(field)}:#{value}"
  end

  def save_incident_fields(prefix, incident_uuid, fields)
    fields.each do |field, value|
      key = get_cache_key_name(prefix, field, value)
      begin
        @memcached.set(key, incident_uuid, @cache_expiration)
      rescue StandardError => e
        @logger.error("Failed to save incident field #{field}: #{e.message}")
      end
    end
  end

  def update_fields_expiration_time(prefix, fields)
    fields.each do |field, value|
      cache_key_name = get_cache_key_name(prefix, field, value)
      begin
        incident_uuid = @memcached.get(cache_key_name)

        next unless incident_uuid

        @memcached.delete(cache_key_name)
        @memcached.set(cache_key_name, incident_uuid, @cache_expiration)
      rescue StandardError => e
        @logger.error("Failed to update expiration time for #{field}: #{e.message}")
      end
    end
  end

  def save_incident_relation(fields, incident_uuid, prefix)
    return if fields.empty?

    partners = fields.map do |f, value|
      begin
        @memcached.get(get_cache_key_name(prefix, f, value))
      rescue StandardError => e
        @logger.error("Failed to retrieve cache key for field #{f}: #{e.message}")
        nil
      end
    end.compact

    partner_uuid = partners.first
    return unless partner_uuid

    cache_relation_key_name = "#{prefix}:relation:#{incident_uuid}"
    begin
      @memcached.set(cache_relation_key_name, partner_uuid)
    rescue StandardError => e
      @logger.error("Failed to save incident relation: #{e.message}")
    end
  end

  def get_priority(event)
    priority = (event.get(PRIORITY) || event.get(SEVERITY) || event.get(SYSLOGSEVERITY_TEXT) || 'unknown').downcase
    unless ['critical', 'high', 'medium', 'low', 'none', 'unknown', 'info', 'emergency', 'alert', 'error', 'warning', 'notice', 'debug'].include?(priority)
      priority = 'unknown'
    end

    priority
  end

  def get_name(event)
    event.get(MSG) || "Unknown incident"
  end

  def get_timestamp(event)
    timestamp = event.get(TIMESTAMP)
    return nil unless timestamp

    Time.at(timestamp)
  end

  def save_incident(prefix, incident)
    return false if incident.empty? || incident[:uuid].nil?

    key = "#{prefix}:incident:#{incident[:uuid]}"
    json_incident = incident.to_json
    begin
      @memcached.set(key, json_incident)
      @logger.info("Incident saved successfully with key: #{key}")
    rescue StandardError => e
      @logger.error("Failed to save incident: #{e.message}")
    end
  end

  def get_key_prefix(event)
    namespace = event.get(NAMESPACE_UUID)
    namespace.nil? ? 'rbincident' : "rbincident:#{namespace}"
  end

  def is_required_priority_or_above?(priority)
    vault_priority_map = {
      'debug': 1,
      'info': 2,
      'notice': 3,
      'warning': 4,
      'error': 5,
      'critical': 6,
      'alert': 7,
      'emergency': 8
    }
    intrusion_priority_map = {
      'info': 1,
      'unknown': 2,
      'none': 3,
      'low': 4,
      'medium': 5,
      'high': 6,
      'critical': 7
    }

    if @incidents_priority_filter
      if @source == 'Intrusion'
        if intrusion_priority_map.key?(priority.to_sym) && intrusion_priority_map.key?(@incidents_priority_filter.to_sym)
          return intrusion_priority_map[priority.to_sym] >= intrusion_priority_map[@incidents_priority_filter.to_sym]
        end
      elsif @source == 'Vault'
        if vault_priority_map.key?(priority.to_sym) && vault_priority_map.key?(@incidents_priority_filter.to_sym)
          return vault_priority_map[priority.to_sym] >= vault_priority_map[@incidents_priority_filter.to_sym]
        end
      end
    end
    false
  end

  def filter(event)
    cache_key_prefix = get_key_prefix(event)
    priority = get_priority(event)

    event_incident_fields = @incident_fields.each_with_object({}) do |field, hash|
      value = event.get(field)
      hash[field] = value if value
    end

    incident_uuid = process_incident(event, event_incident_fields, cache_key_prefix, priority)
    event.set("incident_uuid", incident_uuid) if incident_uuid

    filter_matched(event)
  end

  private

  # Get minimum domain uuid organization < namespaces < service provider
  def get_domain_uuid(event)
    organization_uuid = event.get(ORGANIZATION_UUID)
    return organization_uuid if organization_uuid

    namespace_uuid = event.get(NAMESPACE_UUID)
    return namespace_uuid if namespace_uuid

    service_provider_uuid = event.get(SERVICE_PROVIDER_UUID)
    return service_provider_uuid if service_provider_uuid

    nil
  end

  def process_incident(event, event_incident_fields, cache_key_prefix, priority)
    incident_uuid = nil
    event_incident_fields_scores = calculate_field_scores(event_incident_fields, cache_key_prefix)

    if sufficient_score?(event_incident_fields_scores)
      incident_uuid = process_existing_incident(event_incident_fields, event_incident_fields_scores, cache_key_prefix)
    elsif is_required_priority_or_above?(priority)
      incident_uuid = process_new_incident(event, event_incident_fields, event_incident_fields_scores, cache_key_prefix)
    end

    incident_uuid
  end

  def calculate_field_scores(fields, prefix)
    fields.each_with_object({}) do |(field, value), hash|
      field_score = get_score(field)
      cache_key = get_cache_key_name(prefix, field, value)
      begin
        hash[field] = @memcached.get(cache_key) ? field_score : 0
      rescue StandardError => e
        @logger.error("Failed to get cache key for field #{field}: #{e.message}")
        hash[field] = 0
      end
    end.sort_by { |_key, value| -value }.to_h
  end

  def sufficient_score?(field_scores)
    field_scores.values.sum >= 100
  end

  def process_existing_incident(event_incident_fields, event_incident_fields_scores, cache_key_prefix)
    max_score_field, _max_score = event_incident_fields_scores.first
    begin
      incident_uuid = @memcached.get(get_cache_key_name(cache_key_prefix, max_score_field, event_incident_fields[max_score_field]))
    rescue StandardError => e
      @logger.error("Failed to get existing incident UUID: #{e.message}")
      return
    end

    return unless incident_uuid

    fields_with_no_score = event_incident_fields_scores.select { |_k, v| v.zero? }.keys
    fields_to_save = event_incident_fields.reject { |k, _| !fields_with_no_score.include?(k) }
    fields_to_update = event_incident_fields.reject { |k, _| fields_with_no_score.include?(k) }

    save_incident_fields(cache_key_prefix, incident_uuid, fields_to_save) unless fields_to_save.empty?
    update_fields_expiration_time(cache_key_prefix, fields_to_update)

    incident_uuid
  end

  def process_new_incident(event, event_incident_fields, event_incident_fields_scores, cache_key_prefix)
    incident_uuid = SecureRandom.uuid
    incident = {
      uuid: incident_uuid,
      name: get_name(event),
      priority: get_priority(event),
      source: @source,
      domain_uuid: get_domain_uuid(event),
      first_event_at: get_timestamp(event)
    }

    fields_with_no_score = event_incident_fields_scores.select { |_k, v| v.zero? }.keys
    fields_to_save = event_incident_fields.reject { |k, _| !fields_with_no_score.include?(k) }
    fields_to_update = event_incident_fields.reject { |k, _| fields_with_no_score.include?(k) }

    save_incident(cache_key_prefix, incident) unless incident.empty?
    save_incident_fields(cache_key_prefix, incident_uuid, fields_to_save) unless fields_to_save.empty?
    update_fields_expiration_time(cache_key_prefix, fields_to_update) unless fields_to_update.empty?
    save_incident_relation(fields_to_update, incident_uuid, cache_key_prefix)

    incident_uuid
  end
end
