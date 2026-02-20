package firewall.validation

import rego.v1

default allow := false

allow if {
  count(violations) == 0
}

# -----------------------------
# Reglas principales
# -----------------------------
prod_suffixes := {"DR", "Prod", "Staging"}
nonprod_suffixes := {"Dev", "UAT", "QA"}
get_environment(app) = "prod" if {
  some s_prod
  prod_suffixes[s_prod]
  endswith(app, s_prod)
}

get_environment(app) = "Non-Prod" if {
  some s_prod
  nonprod_suffixes[s_prod]
  endswith(app, s_prod)
}

# Rule 1 - Same app Enviroment 
violations contains msg if {
  input.firewall_rule_request.scope.source_destination_type == "Internal App to Internal App"

  src := input.firewall_rule_request.scope.application_source
  dst := input.firewall_rule_request.scope.application_destination

  src_env := get_environment(src)
  dst_env := get_environment(dst)
  
  src_env != dst_env

  msg := sprintf(
    "Environment mismatch: source '%s' is '%s' while destination '%s' is '%s', Traffic between Prod and Non Prod enviroment is not permitted",
    [src, src_env, dst, dst_env],
  )
}

violations contains msg if {
  input.firewall_rule_request.scope.source_destination_type == "Internal App to External"
  dst = input.firewall_rule_request.scope.application_destination
  msg := sprintf(
    "Destination App is required: External App '%s' cannot be an empty value",
    [dst],
  )
}

#Rule 2 Needs descriptions 
violations contains msg if {
 # not input.firewall_rule_request.purpose.business_justification
  len := count("input.firewall_rule_request.purpose.business_justification")
  len <= 5
  msg := "Business justification must not be empty or description is too short"
}

violations contains msg if {
 input.firewall_rule_request.purpose.business_justification == ""
  msg := "Business justification must not be empty or description is too short"
}

violations contains msg if {
 input.firewall_rule_request.purpose.business_justification == null 
  msg := "Business justification must not be empty or description is too shor"
}

violations contains msg if {
  some i
  rule := input.firewall_rule_request.rules[i]
  not valid_non_empty_array(rule.source)
  msg := sprintf("Source [%d] must be an array with at least one element", [i])
}

violations contains msg if {
  some i
  rule := input.firewall_rule_request.rules[i]
  not valid_non_empty_array(rule.destination)
  msg := sprintf("Destination [%d] must be an array with at least one element", [i])
}

violations contains msg if {
  some i, j
  rule := input.firewall_rule_request.rules[i]
  valid_non_empty_array(rule.source)
  v := rule.source[j]
  not valid_endpoint(v)
  msg := sprintf("The source [%d] in rules[%d] is invalid: %v", [i, j, v])
}

violations contains msg if {
  some i, j
  rule := input.firewall_rule_request.rules[i]
  valid_non_empty_array(rule.destination)
  v := rule.destination[j]
  not valid_endpoint(v)
  msg := sprintf("The destination [%d] in rules[%d] is invalid: %", [i, j, v])
}

# --- CIDR en source debe ser /24..32 (prefijo > 23) ---
violations contains msg if {
  some i, j
  rule := input.firewall_rule_request.rules[i]
  valid_non_empty_array(rule.source)
  v := rule.source[j]

  is_cidr(v)
  not cidr_mask_gt_23(v)

  msg := sprintf("rules[%d].source[%d] CIDR is overly permisive: %v (only /24 a /32 are allowed)", [i, j, v])
}

# --- CIDR en destination debe ser /24..32 (prefijo > 23) ---
violations contains msg if {
  some i, j
  rule := input.firewall_rule_request.rules[i]
  valid_non_empty_array(rule.destination)
  v := rule.destination[j]

  is_cidr(v)
  not cidr_mask_gt_23(v)

  msg := sprintf("rules[%d].destination[%d] CIDR is overly permisive: %v (only /24 a /32 are allowed)", [i, j, v])
}

# -----------------------------
# Puertos no permitidos + Rangos
# -----------------------------

# Puertos bloqueados (strings porque en YAML suelen venir como "443")
disallowed_ports := {
  "20", "21", "22", "25", "587", "465", "80",
  "1433", "3389", "53", "445", "137", "123", "138", "139",
}

# Deniega si se usa un puerto individual bloqueado
violations contains msg if {
  some i, j
  rule := input.firewall_rule_request.rules[i]

  ports := rule.service.port
  valid_non_empty_array(ports)

  raw := ports[j]
  p := sprintf("%v", [raw]) # normaliza a string

  is_port_number(p)
  disallowed_ports[p]

  msg := sprintf("rules[%d].service.port[%d] not an allowed port: %v", [i, j, p])
}

# Deniega si se usa un rango que incluya algún puerto bloqueado
violations contains msg if {
  some i, j
  rule := input.firewall_rule_request.rules[i]

  ports := rule.service.port
  valid_non_empty_array(ports)

  raw := ports[j]
  r := sprintf("%v", [raw]) # normaliza a string

  is_port_range(r)

  # extraer start/end del rango
  parts := split(r, "-")
  start := to_number(parts[0])
  end := to_number(parts[1])

  # encontrar un puerto bloqueado que caiga dentro del rango
  some bad_s
  disallowed_ports[bad_s]
  bad_n := to_number(bad_s)

  start <= bad_n
  bad_n <= end

  msg := sprintf("rules[%d].service.port[%d] range %v contains a non-allowed port: %v", [i, j, r, bad_s])
}

# (Opcional pero recomendado) Deniega puertos con formato inválido
violations contains msg if {
  some i, j
  rule := input.firewall_rule_request.rules[i]

  ports := rule.service.port
  valid_non_empty_array(ports)

  raw := ports[j]
  s := sprintf("%v", [raw])

  not is_port_number(s)
  not is_port_range(s)

  msg := sprintf("rules[%d].service.port[%d] invalid port format: %v (use '443' or '8000-9000')", [i, j, s])
}

# -----------------------------
# NUEVO: Bloquear 0.0.0.0 y 0.0.0.0/0 en source/destination
# -----------------------------

violations contains msg if {
  some i, j
  rule := input.firewall_rule_request.rules[i]
  valid_non_empty_array(rule.source)
  v := rule.source[j]
  is_zero_any(v)
  msg := sprintf("rules[%d].source[%d] cannot be 0.0.0.0 or 0.0.0.0/0: %v", [i, j, v])
}

violations contains msg if {
  some i, j
  rule := input.firewall_rule_request.rules[i]
  valid_non_empty_array(rule.destination)
  v := rule.destination[j]
  is_zero_any(v)
  msg := sprintf("rules[%d].destination[%d] cannot be r 0.0.0.0 or 0.0.0.0/0: %v", [i, j, v])
}

# -----------------------------
# Helpers de estructura
# -----------------------------

valid_non_empty_array(x) if {
  is_array(x)
  count(x) >= 1
}

# -----------------------------
# Validación de endpoints
# -----------------------------

valid_endpoint(v) if { is_string(v); no_wildcards(v); is_ipv4(v) }
valid_endpoint(v) if { is_string(v); no_wildcards(v); is_cidr(v) }
valid_endpoint(v) if { is_string(v); no_wildcards(v); is_ipv4_range(v) }
valid_endpoint(v) if { is_string(v); no_wildcards(v); is_fqdn(v) }
valid_endpoint(v) if { is_string(v); no_wildcards(v); is_url(v) }

# Wildcards prohibidos: "*" y también "%2A" (case-insensitive)
no_wildcards(v) if {
  not contains(v, "*")
  not regex.match("(?i)%2a", v)
}

# -----------------------------
# IPv4 / CIDR / Rangos IPv4
# -----------------------------

octet_re := "^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$"

is_ipv4(v) if {
  regex.match("^([0-9]{1,3}\\.){3}[0-9]{1,3}$", v)
  parts := split(v, ".")
  count(parts) == 4
  not invalid_octet_exists(parts)
}

invalid_octet_exists(parts) if {
  some i
  p := parts[i]
  not regex.match(octet_re, p)
}

is_cidr(v) if {
  regex.match("^([0-9]{1,3}\\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$", v)
  parts := split(v, "/")
  count(parts) == 2
  is_ipv4(parts[0])
}

# máscara /24..32 (prefijo > 23)
cidr_mask_gt_23(v) if {
  regex.match("^([0-9]{1,3}\\.){3}[0-9]{1,3}/(2[4-9]|3[0-2])$", v)
}

is_ipv4_range(v) if {
  regex.match("^([0-9]{1,3}\\.){3}[0-9]{1,3}-([0-9]{1,3}\\.){3}[0-9]{1,3}$", v)
  parts := split(v, "-")
  count(parts) == 2
  is_ipv4(parts[0])
  is_ipv4(parts[1])
}

# -----------------------------
# FQDN y URL
# -----------------------------

is_fqdn(v) if {
  not regex.match("^[a-zA-Z][a-zA-Z0-9+.-]*://", v)
  not contains(v, "/")
  not contains(v, "?")
  not contains(v, "#")
  regex.match("^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$", v)
}

is_url(v) if {
  regex.match("^https?://", v)

  tmp := trim_prefix(v, "http://")
  no_scheme := trim_prefix(tmp, "https://")

  parts := split(no_scheme, "/")
  host_port := parts[0]
  host := split(host_port, ":")[0]

  is_fqdn(host)
}

# -----------------------------
# Helpers de puertos
# -----------------------------

# "1".."65535"
is_port_number(p) if {
  regex.match("^[0-9]{1,5}$", p)
  n := to_number(p)
  n >= 1
  n <= 65535
}

# "start-end" (ambos 1..65535, start <= end)
is_port_range(r) if {
  regex.match("^[0-9]{1,5}-[0-9]{1,5}$", r)
  parts := split(r, "-")
  count(parts) == 2

  a := parts[0]
  b := parts[1]

  is_port_number(a)
  is_port_number(b)

  na := to_number(a)
  nb := to_number(b)
  na <= nb
}

# helper: detecta 0.0.0.0 o 0.0.0.0/0
is_zero_any(v) if { v == "0.0.0.0" }
is_zero_any(v) if { v == "0.0.0.0/0" }