rule detect_ransomware_mass_encryption {
  meta:
    description = "Detects potential ransomware through rapid file modifications"
    author = "Handyman"
    severity = "Critical"
    mitre_attack_tactic = "Impact"
    mitre_attack_technique = "T1486 - Data Encrypted for Impact"
    
  events:
    $file_modify.metadata.event_type = "FILE_MODIFICATION"
    $file_modify.target.file.full_path = /.*\.(encrypted|locked|crypto|crypt)$/
    $file_modify.principal.hostname = $hostname
    
  match:
    $hostname over 5m
    
  condition:
    $file_modify > 50
    
  outcome:
    $risk_score = 95
    $hostname
    $file_count = count_distinct($file_modify.target.file.full_path)
    $process_name = $file_modify.principal.process.file.full_path
}
