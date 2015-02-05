filter {
  if [type] == "imperva" {
#    grok {
#       match => { "message" => "<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
#
#      add_field => [ "received_at", "%{@timestamp}" ]
#      add_field => [ "received_from", "%{host}" ]
#      add_tag => [ "imperva-basicgrok" ]
#    }
#    syslog_pri { }
#    date {
#      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
#      add_tag => [ "imperva-date" ]
#    }
     json {
         source => "message"
         add_tag => [ "imperva-json" ]
#         include_keys => ["MessageSourceAddress","EventReceivedTime","SourceModuleName","Hostname","EventTime","Message"]
     }
     kv {
        source => "Message"
        field_split => ";"
        add_tag => [ "imperva-kv" ]
         include_keys => ["Action","DestinationIP","DestinationPort","UserName","SourceIP","SourcePort","Protocol","EventTime","Category","Policy","GroupName","ServiceName","Application","Description"]
     }
     date {
      match => [ "EventTime", "MMM d YYYY HH:mm:ss", "MMM dd YYYY HH:mm:ss" ]
      add_tag => [ "imperva-date" ]
    }
    mutate {
        remove_field => [ "message" ]
        remove_field => [ "SyslogFacility", "SyslogFacilityName", "SyslogSeverity", "SyslogSeverityValue", "Severity", "SeverityValue" ]
        remove_field => [ "SourcePort", "SourceModuleName" ] 
    }
  }
}

