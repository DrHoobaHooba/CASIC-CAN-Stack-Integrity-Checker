<?xml version="1.0" encoding="UTF-8"?>
<ModuleDescription>
  <Object Index="0x3000" Name="NodeMode" DataType="UNSIGNED8" AccessType="rw" />
  <Object Index="0x3001" Name="Temperature">
    <SubObject SubIndex="0x00" Name="TempC" DataType="INTEGER16" AccessType="ro" LowLimit="-40" HighLimit="125" />
  </Object>
  <CommunicationObject Name="RPDO1" CobId="0x200" />
</ModuleDescription>
