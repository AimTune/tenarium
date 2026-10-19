import { themes as prismThemes } from 'prism-react-renderer';
import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const repoUrl = 'https://github.com/AimTune/tenarium';

const config: Config = {
  title: 'Tenarium',
  tagline: 'The open-source tenant control plane for multi-tenant SaaS',
  favicon: 'img/favicon.svg',

  url: 'https://tenarium.aimtune.dev',
  baseUrl: '/',
  trailingSlash: false,

  organizationName: 'AimTune',
  projectName: 'tenarium',

  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  markdown: {
    // .md files are plain CommonMark (they contain `<`, `{`, ...); only .mdx is MDX.
    format: 'detect',
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'tr'],
    localeConfigs: {
      en: { label: 'English', htmlLang: 'en' },
      tr: { label: 'Türkçe', htmlLang: 'tr' },
    },
  },

  presets: [
    [
      'classic',
      {
        docs: {
          // The docs stay in the repository's top-level docs/ folder.
          path: '../docs',
          routeBasePath: 'docs',
          sidebarPath: './sidebars.ts',
          editUrl: ({ docPath }) => `${repoUrl}/edit/main/docs/${docPath}`,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: [
    [
      '@easyops-cn/docusaurus-search-local',
      {
        hashed: true,
        language: ['en', 'tr'],
        indexBlog: false,
        docsRouteBasePath: 'docs',
        docsDir: '../docs',
        highlightSearchTermsOnTargetPage: true,
      },
    ],
  ],

  themeConfig: {
    
    colorMode: {
      defaultMode: 'light',
      respectPrefersColorScheme: true,
    },
    docs: {
      sidebar: { hideable: true },
    },
    navbar: {
      title: 'Tenarium',
      logo: {
        alt: 'Tenarium logo',
        src: 'img/logo.svg',
      },
      items: [
        { type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs' },
        { type: 'doc', docId: 'plugins/README', position: 'left', label: 'Plugins' },
        { to: 'pathname:///api/', position: 'left', label: 'API reference' },
        { type: 'localeDropdown', position: 'right' },
        {
          href: repoUrl,
          position: 'right',
          className: 'header-github-link',
          'aria-label': 'GitHub repository',
          label: 'GitHub',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            { label: 'Introduction', to: '/docs' },
            { label: 'Configuration', to: '/docs/configuration' },
            { label: 'Plugins', to: '/docs/plugins' },
            { label: 'API reference', to: 'pathname:///api/' },
          ],
        },
        {
          title: 'Community',
          items: [
            { label: 'Issues', href: `${repoUrl}/issues` },
            { label: 'Contributing', href: `${repoUrl}/blob/main/CONTRIBUTING.md` },
            { label: 'Security policy', href: `${repoUrl}/blob/main/SECURITY.md` },
          ],
        },
        {
          title: 'More',
          items: [
            { label: 'GitHub', href: repoUrl },
            { label: 'Releases', href: `${repoUrl}/releases` },
            { label: 'Changelog', href: `${repoUrl}/blob/main/CHANGELOG.md` },
            { label: 'Roadmap', to: '/docs/roadmap' },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Tenarium contributors. Released under the MIT License.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['go', 'yaml', 'bash', 'json', 'typescript', 'python'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
