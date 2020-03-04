 
Configuration LCMConfig

  {

  Node $env:COMPUTERNAME

  {

  LocalConfigurationManager

  {

  ConfigurationModeFrequencyMins = 30

  ConfigurationMode = "ApplyAndAutocorrect"

  RebootNodeIfNeeded = $true

  }

  }

  }


# Invoke the DSC  Functions and creat the MOF Files

  LCMConfig -OutputPath "C:\DSCConfigs"




# Set the Local Config  Manager to use the new MOF for config

Set-DscLocalConfigurationManager  -Path "C:\DSCConfigs"


 
