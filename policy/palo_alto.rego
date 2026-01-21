package palo_alto.compliance

# Definimos una regla que agrupa todas las violaciones encontradas
violations[msg] {
    # 1. Iteramos sobre las reglas del JSON de entrada
    rule := input.rules[_]
    
    # 2. Condición: La regla permite tráfico a "any"
    rule.to == "any"
    
    # 3. Mensaje de error personalizado
    msg := sprintf("Regla insegura detectada: '%s' tiene 'any' como destino.", [rule.name])
}

# Regla booleana simple
default allow = false
allow {
    count(violations) == 0
}