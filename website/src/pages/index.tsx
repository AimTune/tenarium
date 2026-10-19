import type { ReactNode } from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import Translate, { translate } from '@docusaurus/Translate';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import CodeBlock from '@theme/CodeBlock';

import styles from './index.module.css';

type Feature = {
  title: string;
  description: string;
  to: string;
};

const features: Feature[] = [
  {
    title: translate({ id: 'home.features.lifecycle.title', message: 'Tenant lifecycle' }),
    description: translate({
      id: 'home.features.lifecycle.description',
      message:
        'A strict state machine with hierarchy, labels, JSON-Schema-validated settings, optimistic locking and idempotent creates. Scheduled actions and trials, soft deletion with restore, templates and custom domains.',
    }),
    to: '/docs/tenants',
  },
  {
    title: translate({ id: 'home.features.plans.title', message: 'Plans, entitlements and usage' }),
    description: translate({
      id: 'home.features.plans.description',
      message:
        'Features and limits per plan with per-tenant overrides, plan revisions and add-ons, atomic usage counters with soft limits and threshold events, and metering exports to Stripe, Lago, Orb and OpenMeter.',
    }),
    to: '/docs/plans',
  },
  {
    title: translate({ id: 'home.features.users.title', message: 'Users, SSO and passkeys' }),
    description: translate({
      id: 'home.features.users.description',
      message:
        'Platform-wide users with memberships in many tenants, invitations, two-factor authentication, passkeys, magic links and social login. Per-tenant OIDC and SAML single sign-on and SCIM 2.0 provisioning.',
    }),
    to: '/docs/users',
  },
  {
    title: translate({ id: 'home.features.oidc.title', message: 'OpenID Connect provider' }),
    description: translate({
      id: 'home.features.oidc.description',
      message:
        'Use Tenarium as the sign-in service of your applications: authorization code flow with PKCE, consent, discovery and JWKS with signing key rotation.',
    }),
    to: '/docs/oidc-provider',
  },
  {
    title: translate({ id: 'home.features.events.title', message: 'Reliable event outbox' }),
    description: translate({
      id: 'home.features.events.description',
      message:
        'Every change is written with its event in one PostgreSQL transaction. Each subscription has its own cursor, retries with backoff, a dead-letter queue and replay. Events are CloudEvents 1.0.',
    }),
    to: '/docs/architecture',
  },
  {
    title: translate({ id: 'home.features.plugins.title', message: 'Plugins in any language' }),
    description: translate({
      id: 'home.features.plugins.description',
      message:
        'Compile plugins in with Go, run them out of process in any language, or sandbox them as WebAssembly. SDKs for Go, TypeScript and Python, plus built-in plugins for Kafka, Keycloak, Stripe, PostgreSQL, Kubernetes, S3 and more.',
    }),
    to: '/docs/plugins',
  },
  {
    title: translate({ id: 'home.features.auth.title', message: 'Authentication and authorization' }),
    description: translate({
      id: 'home.features.auth.description',
      message:
        'API keys, OIDC, LDAP and tenant API keys; role-based access control, tenant-scoped administrators, custom tenant roles and groups, and authorizer plugins for OpenFGA, SpiceDB, OPA and Cedar.',
    }),
    to: '/docs/auth',
  },
  {
    title: translate({ id: 'home.features.integrate.title', message: 'Integrates with your stack' }),
    description: translate({
      id: 'home.features.integrate.description',
      message:
        'A Go client and the tenariumctl CLI, tenant middleware for Go, TypeScript and Python services, gateway integration for Envoy, NGINX and Traefik, and PostgreSQL row-level security helpers.',
    }),
    to: '/docs/middleware',
  },
  {
    title: translate({ id: 'home.features.ops.title', message: 'Built for operations' }),
    description: translate({
      id: 'home.features.ops.description',
      message:
        'Embedded admin UI, OpenAPI 3.1, Prometheus metrics, OpenTelemetry tracing, horizontal scaling with leases, managed TLS certificates, KMS envelope encryption, a Helm chart, a Kubernetes operator and a Terraform provider.',
    }),
    to: '/docs/operations',
  },
];

const dockerSnippet = [
  'git clone https://github.com/AimTune/tenarium.git && cd tenarium',
  'docker compose up -d',
  '# Admin UI: http://localhost:8080/ui/  (API key: dev-key)',
].join('\n');

const sourceSnippet = [
  'TENARIUM_API_KEY=dev go run ./cmd/tenarium -config config.example.yaml',
  '',
  'curl -H "Authorization: Bearer dev" -H "Content-Type: application/json" \\',
  `  -d '{"slug": "acme", "name": "Acme Inc", "plan": "free"}' \\`,
  '  http://localhost:8080/v1/tenants',
].join('\n');

function Hero(): ReactNode {
  return (
    <header className={styles.hero}>
      <div className="container">
        <img className={styles.logo} src={useBaseUrl('/img/logo.svg')} alt="" />
        <Heading as="h1" className={styles.title}>
          Tenarium
        </Heading>
        <p className={styles.tagline}>
          <Translate id="home.tagline">
            The open-source tenant control plane for multi-tenant SaaS: tenant lifecycle, plans and
            usage, users and single sign-on, and a reliable event log that plugins build on.
          </Translate>
        </p>
        <div className={styles.buttons}>
          <Link className="button button--primary button--lg" to="/docs">
            <Translate id="home.cta.getStarted">Get started</Translate>
          </Link>
          <Link
            className="button button--secondary button--lg"
            href="https://github.com/AimTune/tenarium">
            <Translate id="home.cta.github">View on GitHub</Translate>
          </Link>
        </div>
      </div>
    </header>
  );
}

function Features(): ReactNode {
  return (
    <section className={styles.section}>
      <div className="container">
        <Heading as="h2" className={styles.sectionTitle}>
          <Translate id="home.features.heading">What Tenarium does</Translate>
        </Heading>
        <p className={styles.sectionLead}>
          <Translate id="home.features.lead">
            One service owns your tenants, so your applications do not have to.
          </Translate>
        </p>
        <div className={styles.grid}>
          {features.map((f) => (
            <Link key={f.to} to={f.to} className={styles.card}>
              <Heading as="h3">{f.title}</Heading>
              <p>{f.description}</p>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

function QuickStart(): ReactNode {
  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <Heading as="h2" className={styles.sectionTitle}>
          <Translate id="home.quickstart.heading">Quick start</Translate>
        </Heading>
        <p className={styles.sectionLead}>
          <Translate id="home.quickstart.lead">
            Run Tenarium with PostgreSQL and Kafka in Docker, or from source with an in-memory
            store.
          </Translate>
        </p>
        <div className={styles.quickstart}>
          <Heading as="h3">
            <Translate id="home.quickstart.docker">With Docker Compose</Translate>
          </Heading>
          <CodeBlock language="bash">{dockerSnippet}</CodeBlock>
          <Heading as="h3">
            <Translate id="home.quickstart.source">From source</Translate>
          </Heading>
          <CodeBlock language="bash">{sourceSnippet}</CodeBlock>
          <p>
            <Translate
              id="home.quickstart.next"
              values={{
                config: (
                  <Link to="/docs/configuration">
                    <Translate id="home.quickstart.next.config">configuration reference</Translate>
                  </Link>
                ),
                api: (
                  <Link to="pathname:///api/">
                    <Translate id="home.quickstart.next.api">API reference</Translate>
                  </Link>
                ),
              }}>
              {'Next: read the {config} or browse the {api}.'}
            </Translate>
          </p>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title={translate({ id: 'home.meta.title', message: 'Open-source tenant control plane' })}
      description={translate({
        id: 'home.meta.description',
        message:
          'Tenarium is an open-source tenant control plane for multi-tenant SaaS applications: tenant lifecycle, plans, entitlements, usage, users, single sign-on and a plugin system.',
      })}>
      <Hero />
      <main>
        <Features />
        <QuickStart />
      </main>
    </Layout>
  );
}
