package palo_alto.compliance

import rego.v1

# Regla para detectar violaciones
violations[msg] if {
    # Navegamos por la estructura exacta del JSON
    # El [_] le dice a OPA: "recorre todos los elementos de esta lista"
    rule := input.result.config.devices.entry[_].vsys.entry[_].rulebase.security.rules.entry[_]
    
    # Condición: Evaluamos si en la lista 'to' existe el valor "any"
    rule.to[_] == "any"
    
    # Generamos el mensaje de error
    msg := sprintf("Seguridad: La regla '%s' permite tráfico hacia 'any' (Inseguro)", [rule.name])
}
violations[msg] if {
    # Navegamos por la estructura exacta del JSON
    # El [_] le dice a OPA: "recorre todos los elementos de esta lista"
    rule := input.result.config.devices.entry[_].vsys.entry[_].rulebase.security.rules.entry[_]
    
    # Condición: Evaluamos si en la lista 'to' existe el valor "any"
    rule.destination[_] == "any"
    
    # Generamos el mensaje de error
    msg := sprintf("Seguridad: La regla '%s' no puede tener un any como destination", [rule.name])
}
# Resultado global
default allow = false
allow if {
    count(violations) == 0
}