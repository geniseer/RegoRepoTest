package palo_alto.compliance
import rego.v1
violations[msg] if {
    rule := input.result.config.devices.entry[_].vsys.entry[_].rulebase.security.rules.entry[_]
    rule.to[_] == "any"
    msg := sprintf("Seguridad: La regla '%s' permite tráfico hacia 'any' (Inseguro)", [rule.name])
}
violations[msg] if {
    rule := input.result.config.devices.entry[_].vsys.entry[_].rulebase.security.rules.entry[_]
    rule.destination[_] == "any"
    msg := sprintf("Seguridad: La regla '%s' no puede tener un any como destination", [rule.name])
}
default allow = false
allow if {
    count(violations) == 0
}
