require 'pundit'

module JSONAPI
  module Authorization
    module PunditScopedResource
      extend ActiveSupport::Concern

      module ClassMethods
        def records(options = {})
          context = options[:context]
          user_context = JSONAPI::Authorization.configuration.user_context(context)
          namespace = JSONAPI::Authorization.configuration.namespace(context)
          if _policy_klass
            _policy_klass::Scope.new(user_context, _model_class).resolve
          else
            ::Pundit.policy_scope!(user_context, namespace + [_model_class])
          end
        end
      end

      def records_for(association_name)
        record_or_records = @model.public_send(association_name)
        relationship = fetch_relationship(association_name)
        case relationship
        when JSONAPI::Relationship::ToOne
          record_or_records
        when JSONAPI::Relationship::ToMany
          user_context = JSONAPI::Authorization.configuration.user_context(context)
          namespace = JSONAPI::Authorization.configuration.namespace(context)
          if self.class._policy_klass
            self.class._policy_klass::Scope.new(user_context, record_or_records).resolve
          else
            ::Pundit.policy_scope!(user_context, namespace + [record_or_records])
          end
        else
          raise "Unknown relationship type #{relationship.inspect}"
        end
      end

      private

      def fetch_relationship(association_name)
        relationships = self.class._relationships.select do |_k, v|
          v.relation_name(context: context) == association_name
        end
        if relationships.empty?
          nil
        else
          relationships.values.first
        end
      end
    end
  end
end
