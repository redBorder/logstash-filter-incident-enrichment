# The Configuration module provides a flexible and dynamic way to handle
# configurations within Ruby applications. It allows for the dynamic definition and access
# of configuration variables without the need for pre-declaring each one.
#
# Features:
# - Enables dynamic definition of access methods (getters and setters) for any
#   specified configuration.
# - Access methods are created only when needed, avoiding the overhead of defining
#   methods that may never be used.
# - Facilitates the management of configurations in applications where the set of
#   configurations can change or expand over time.
module Configuration
  class << self
    def set_config(key, value)
      # Define getter if doesnt exists yet
      unless respond_to?(key)
        define_singleton_method(key) do
          instance_variable_get("@#{key}")
        end
      end

      # Define setter if doesnt exists yet
      setter_method_name = "#{key}="
      unless respond_to?(setter_method_name)
        define_singleton_method(setter_method_name) do |value|
          instance_variable_set("@#{key}", value)
        end
      end

      # Set the value of the instance variable
      send(setter_method_name, value)
    end
  end
end
