import fs from 'node:fs';

const now = new Date().toISOString();
const md = `# Latest digest

Generated at: ${now}

> PR collection will be implemented next.
`;

fs.writeFileSync('docs/index.md', md);
console.log('Generated docs/index.md');
