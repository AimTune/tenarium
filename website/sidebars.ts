import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

// Mirrors the navigation of the former mkdocs.yml.
const sidebars: SidebarsConfig = {
  docs: [
    { type: 'doc', id: 'index', label: 'Home' },
    {
      type: 'category',
      label: 'Using Tenarium',
      collapsed: false,
      items: [
        { type: 'doc', id: 'configuration', label: 'Configuration' },
        { type: 'doc', id: 'api', label: 'REST API' },
        { type: 'doc', id: 'tenants', label: 'Tenant lifecycle' },
        { type: 'doc', id: 'plans', label: 'Plans and placement' },
        { type: 'doc', id: 'users', label: 'Users' },
        { type: 'doc', id: 'auth', label: 'Authentication and authorization' },
        { type: 'doc', id: 'oidc-provider', label: 'OpenID provider' },
        { type: 'doc', id: 'webhooks', label: 'Tenant webhooks' },
        { type: 'doc', id: 'event-schemas', label: 'Event schema registry' },
        { type: 'doc', id: 'privacy', label: 'Data protection' },
      ],
    },
    {
      type: 'category',
      label: 'Integrating',
      items: [
        { type: 'doc', id: 'client', label: 'Go client and tenariumctl' },
        { type: 'doc', id: 'middleware', label: 'Tenant middleware' },
        { type: 'doc', id: 'gateway', label: 'Gateway integration' },
        { type: 'doc', id: 'rls', label: 'PostgreSQL row-level security' },
      ],
    },
    {
      type: 'category',
      label: 'Plugins',
      link: { type: 'doc', id: 'plugins/README' },
      items: [
        { type: 'doc', id: 'plugins/writing-go', label: 'Writing Go plugins' },
        { type: 'doc', id: 'plugins/external', label: 'External plugins' },
        { type: 'doc', id: 'plugins/wasm', label: 'WebAssembly plugins' },
        { type: 'doc', id: 'plugins/archive', label: 'Event archive' },
      ],
    },
    {
      type: 'category',
      label: 'Running Tenarium',
      items: [
        { type: 'doc', id: 'operations', label: 'Operations' },
        { type: 'doc', id: 'tls', label: 'TLS and managed certificates' },
        { type: 'doc', id: 'secrets', label: 'Secrets at rest' },
        { type: 'doc', id: 'multi-region', label: 'Multi-region deployments' },
        { type: 'doc', id: 'architecture', label: 'Architecture' },
        { type: 'doc', id: 'testing', label: 'Testing' },
      ],
    },
    { type: 'doc', id: 'roadmap', label: 'Roadmap' },
  ],
};

export default sidebars;
