rule detect_remote_admin_file_access {
  meta:
    description = "Alert when admin.txt is accessed from a remote location"
    author = "handyman"
    severity = "High"
    
  events:
    $file_access.metadata.event_type = "FILE_OPEN"
    $file_access.target.file.full_path = /.*admin.txt.*/
    $file_access.principal.hostname != $file_access.target.hostname
    
  condition:
    $file_access over 5m
}
