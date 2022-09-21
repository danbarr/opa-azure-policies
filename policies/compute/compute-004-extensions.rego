package terraform.policies.azure.compute_004

import future.keywords.in
import input.plan as tfplan

actions := [
	["no-op"],
	["create"],
	["update"],
]

approved_publishers := [
    "Datadog",
    "Microsoft"
]

resources := [resource_changes |
	resource_changes := tfplan.resource_changes[_]
	resource_changes.type == "azurerm_virtual_machine_extension"
	resource_changes.mode == "managed"
	resource_changes.change.actions in actions
]

violations := [resource |
	resource := resources[_]
    strings.any_prefix_match(resource.change.after.publisher, approved_publishers)
]

violators[address] {
	address := violations[_].address
}

# METADATA
# title: AZURE-COMPUTE-004
# description: Extensions must be from approved publishers
# custom:
#  severity: medium
#  enforcement_level: mandatory
# authors:
# - name: Dan Barr
# organizations:
# - HashiCorp
rule[result] {
	count(violations) != 0
	result := {
		"policy": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"severity": rego.metadata.rule().custom.severity,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"resources": {
			"count": count(violations),
			"addresses": violators,
		},
	}
}