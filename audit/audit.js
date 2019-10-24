const child_process = require('child_process');
const whiteList = require('./whitelist.json');

child_process.exec('npm audit --json', (err, stdout, stderr) => {
  let auditResult = JSON.parse(stdout.toString());
  processAuditResult(auditResult);
});

function processAuditResult(auditResult) {
  let foundVulnerabilities = [];
  let list = [];

  if (auditResult.actions) {
    auditResult.actions.map(item => foundVulnerabilities = foundVulnerabilities.concat(item.resolves));
  }

  foundVulnerabilities.map((item) => {
    if (!checkWhiteList(item)) {
      list.push(item);
    }
  });

  if (list.length) {
    let listOfIssues = list.map((issueItem, index) => {
      return `
    ${index + 1}
    ----------
    id:${issueItem.id} 
    path:${issueItem.path} 
    dev:${issueItem.dev} 
    optional:${issueItem.optional} 
    bundled:${issueItem.bundled} 
    ----------`;
    });

    throw `found vulnerabilities 
    ${JSON.stringify(auditResult.metadata.vulnerabilities)}
    try to fix them by running "npm audit fix"
    ${listOfIssues}`;


  } else if (auditResult.error) {
    console.log('Error in NPM audit');
    console.log(auditResult.error);
  } else {
    console.log(`found vulnerabilities 
    ${JSON.stringify(auditResult.metadata.vulnerabilities)}
    these vulnerabilities are listed in whitelist.json,
    try to fix them by running "npm audit fix"`)
  }
}

function checkWhiteList(issue) {
  return whiteList.list.filter(item => item.id === issue.id && item.path === issue.path)[0]
}
