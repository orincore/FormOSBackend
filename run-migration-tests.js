/**
 * Programmatic runner for ts-node to execute the migration test suite.
 */
require('ts-node').register({
  compilerOptions: {
    module: 'commonjs',
    moduleResolution: 'node',
    target: 'ES2020'
  }
});

require('./test-migration.ts');
