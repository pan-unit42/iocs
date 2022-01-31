//Description: VNC Command Line Arguments
config case_sensitive = false
|dataset = xdr_data
|filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
|filter action_process_image_command_line contains "-autoreconnect" AND action_process_image_command_line contains "-id:" AND action_process_image_command_line contains "-connect"
|fields _time, agent_hostname, actor_effective_username, actor_process_image_sha256,action_process_image_path, action_process_image_command_line, action_process_image_sha256, actor_process_image_path,  actor_process_command_line 
