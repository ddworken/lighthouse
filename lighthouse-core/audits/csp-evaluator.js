/**
 * @license Copyright 2020 The Lighthouse Authors. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
'use strict';

const Audit = require('./audit.js');
const MainResource = require('../computed/main-resource.js');
const i18n = require('../lib/i18n/i18n.js');
const {evaluateRawCspForFailures, evaluateRawCspForWarnings} = require('../lib/csp-evaluator.js');

/** @typedef {import('../lib/csp-evaluator.js').Finding} Finding */

const UIStrings = {
  title: 'CSP is robust against XSS attacks',
  failureTitle: 'CSP is not robust against XSS attacks',
  description: 'A strong Content Security Policy (CSP) can significantly ' +
    'reduce the risk of XSS attacks. ' +
    '[Learn more](https://developers.google.com/web/fundamentals/security/csp)',
  metaTagWarning: 'The page contains a CSP defined in a meta tag. ' +
    'It is not recommended to use a CSP this way, ' +
    'please define the CSP in an HTTP header instead. ' +
    'Lighthouse will ignore any CSP defined in a meta tag.',
  noCsp: 'Does not have a CSP',
};

const str_ = i18n.createMessageInstanceIdFn(__filename, UIStrings);

/** @type {Record<number, string>} */
const SEVERITIES = {
  10: 'High',
  20: 'Syntax',
  30: 'Medium',
  40: 'Possible High',
  45: 'Strict CSP',
  50: 'Possible Medium',
  60: 'Info',
  100: 'None',
};

class CSPEvaluator extends Audit {
  /**
   * @return {LH.Audit.Meta}
   */
  static get meta() {
    return {
      id: 'csp-evaluator',
      title: str_(UIStrings.title),
      failureTitle: str_(UIStrings.failureTitle),
      description: str_(UIStrings.description),
      requiredArtifacts: ['devtoolsLogs', 'MetaElements', 'URL'],
    };
  }

  /**
   * @param {Array<Finding>} findings
   * @return {LH.Audit.Details.TableItem[]}
   */
  static constructResults(findings) {
    const findingsByDirective = findings
      .sort((a, b) => a.severity - b.severity)
      .reduce((findingsByDirective, f) => {
        const directiveFindings = findingsByDirective[f.directive] || [];
        directiveFindings.push(f);
        findingsByDirective[f.directive] = directiveFindings;
        return findingsByDirective;
      }, /** @type {Record<string, Array<Finding>>} */ ({}));

    /** @type {LH.Audit.Details.TableItem[]} */
    const results = [];
    for (const [directive, findings] of Object.entries(findingsByDirective)) {
      // Lower numbers correspond to higher severities. Use highest severity finding (lowest number).
      const minSeverity = findings.reduce((min, f) => Math.min(min, f.severity), 100);
      const severity = SEVERITIES[minSeverity];

      // A finding with undefined value applies to the whole directive.
      const noValueIndex = findings.findIndex(f => !f.value);
      const description
        = noValueIndex !== -1 ? findings.splice(noValueIndex, 1)[0].description : undefined;

      results.push({
        directive,
        severity,
        description,
        subItems: {
          type: 'subitems',
          items: findings
            .filter(f => f.value)
            .map(f => {
              // Replace severity number with descriptive text.
              return {...f, severity: SEVERITIES[f.severity]};
            }),
        },
      });
    }
    return results;
  }

  /**
   * @param {LH.Artifacts} artifacts
   * @param {LH.Audit.Context} context
   * @return {Promise<LH.Audit.Product>}
   */
  static async audit(artifacts, context) {
    const devtoolsLog = artifacts.devtoolsLogs[Audit.DEFAULT_PASS];
    const mainResource = await MainResource.request({devtoolsLog, URL: artifacts.URL}, context);

    // CSP defined in meta tag is not recommended, warn if a CSP is defined this way.
    const hasCspMetaTags = Boolean(artifacts.MetaElements.find(m => {
      return m.httpEquiv && m.httpEquiv.toLowerCase() === 'content-security-policy';
    }));
    const warnings = hasCspMetaTags ? [UIStrings.metaTagWarning] : [];

    const cspHeaders = mainResource.responseHeaders.filter(h => {
      return h.name.toLowerCase() === 'content-security-policy';
    }).map(h => h.value);
    if (cspHeaders.length == 0) {
      return {
        warnings,
        score: 0,
        notApplicable: false,
        displayValue: UIStrings.noCsp,
      };
    }
    const findings = evaluateRawCspForFailures(cspHeaders);
    warnings.push(...evaluateRawCspForWarnings(cspHeaders).map(f => f.description));
    const results = this.constructResults(findings);
    /** @type {LH.Audit.Details.Table['headings']} */
    const headings = [
      /* eslint-disable max-len */
      {key: 'directive', itemType: 'code', subItemsHeading: {key: 'value', itemType: 'code'}, text: 'Directive'},
      {key: 'severity', itemType: 'text', subItemsHeading: {key: 'severity'}, text: 'Severity'},
      {key: 'description', itemType: 'text', subItemsHeading: {key: 'description'}, text: 'Description'},
      /* eslint-enable max-len */
    ];
    const details = Audit.makeTableDetails(headings, results);
    return {
      warnings,
      score: findings.length > 0 ? 0 : 1,
      notApplicable: false,
      details,
    };
  }
}

module.exports = CSPEvaluator;
module.exports.UIStrings = UIStrings;
