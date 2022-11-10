require 'pundit'

module JSONAPI
  module Authorization
    class PolicyHelper
      attr_reader :user, :namespace, :resource_namespace

      def initialize(user:,namespace:,resource_namespace:)
        @user = user
        @namespace = namespace
        @resource_namespace = resource_namespace
      end

      def get_policy(record)
        namespace.empty? ? record : namespace + [record]
      end

      def get_policy_klass(record)
        resource_klass = get_resource_klass(record)
        return resource_klass._policy_klass if resource_klass && resource_klass._policy_klass
      end

      def get_resource_klass(record)
        record_klass = record.is_a?(Class) ? record : record.class
        resource_klass_fragments = []
        if resource_namespace
          resource_klass_fragments += resource_namespace.map(&:capitalize)
        end
        resource_klass_fragments << "#{record_klass.name}Resource"
        resource_klass_fragments.join('::').safe_constantize
      end

      def pundit_authorize(record, action, source_resource_klass = nil)
        if source_resource_klass
          record_klass = record.is_a?(Class) ? record : record.class
          resource_relationships = source_resource_klass._relationships.values.find { |r| r.name === record.class.name.downcase }
        end

        policy_klass = get_policy_klass(record)
        if policy_klass
          ::Pundit.authorize(user, record, action, policy_class: policy_klass)
        else
          ::Pundit.authorize(user, get_policy(record), action)
        end
      end


      def pundit_policy(record)
        policy_klass = get_policy_klass(record)
        if policy_klass
          ::Pundit.policy(user, record, policy_class: policy_klass)
        else
          ::Pundit.policy(user, get_policy(record))
        end
      end

      def policy_scope!(record)
        policy_klass = get_policy_klass(record)

        if policy_klass
          policy_klass::Scope.new(user, record)
        else
          ::Pundit.policy_scope!(user, namespace + [record])
        end
      end
    end
  end
end
