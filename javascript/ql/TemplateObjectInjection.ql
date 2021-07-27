/**
 * @name Template Object Injection
 * @description Instantiating a template using a user-controlled object is vulnerable to local file read and potential remote code execution.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.1
 * @precision low
 * @id js/template-object-injection-tug
 * @tags security
 *       external/cwe/cwe-073
 *       external/cwe/cwe-094
 */

import javascript
import DataFlow::PathGraph
import semmle.javascript.security.dataflow.TemplateObjectInjection::TemplateObjectInjection

from DataFlow::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Template object injection due to $@.", source.getNode(),
  "user-provided value"
