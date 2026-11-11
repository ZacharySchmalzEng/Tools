export type OperatingSystem = 'windows' | 'linux';

export interface ScriptItem {
  id: string;
  name: string;
  path: string;
  os: OperatingSystem | 'cross-platform';
  category: 'Provisioning' | 'Gaming' | 'Maintenance' | 'Networking' | 'Backups' | 'Data Management' | 'Docs';
  language: 'bash' | 'powershell' | 'markdown';
  description: string;
  version: string;
  author: string;
  requiresElevation: boolean;
  supportedDistrosOrEditions: string[];
  keyFeatures: string[];
  flags?: FlagDefinition[];
}

export interface FlagDefinition {
  flag: string;
  name: string;
  description: string;
  category: 'profile' | 'core' | 'apps' | 'security' | 'modifier';
  dangerous?: boolean;
  warningNote?: string;
  associatedSoftware?: string[];
}

export interface WindowsDeploymentConfig {
  profile: 'Standard' | 'Complete' | 'Light' | 'Custom';
  system: boolean;
  debloat: boolean;
  security: boolean;
  dev: boolean;
  dualBoot: boolean;
  apps: boolean;
  devApps: boolean;
  creators: boolean;
  cyber: boolean;
  maker: boolean;
  gaming: boolean;
  nvidia: boolean;
  autoUpdate: boolean;
  maintenance: boolean;
  uninstall: boolean;
}

export interface LinuxDeploymentConfig {
  preset: 'baseline' | 'strict' | 'gaming' | 'developer' | 'custom';
  distro: 'rpm' | 'nobara' | 'atomic' | 'arch' | 'steamos' | 'opensuse' | 'deb';
  gpu: 'nvidia' | 'amd' | 'none';
  desktopEnv: 'kde' | 'gnome' | 'cosmic' | 'xfce' | 'cinnamon';
  all: boolean;
  update: boolean;
  apps: boolean;
  devapps: boolean;
  cyber: boolean;
  sysadmin: boolean;
  maker: boolean;
  creators: boolean;
  gaming: boolean;
  ssh: boolean;
  discord: boolean;
  harden: boolean;
  hardenAdvanced: boolean;
  twoFactor: boolean;
  autoYes: boolean;
  downloadOnly: boolean;
  unattended: boolean;
  debug: boolean;
}

export interface TerminalLogEntry {
  id: string;
  timestamp: string;
  type: 'info' | 'success' | 'warn' | 'error' | 'cmd' | 'header';
  text: string;
}
