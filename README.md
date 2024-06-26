# ble uart with AES-CCM Sample

# 준비사항
1. softdevice 17.1.0 다운로드
2. ses 5.42a 다운로드
3. gcc 다운로드 : https://developer.arm.com/downloads/-/gnu-rm/9-2020-q2-update
4. external/micro-ecc의 build_all.bat 스크립트를 실행해야 라이브러리가 생성되며, 해당 앱에서 이 라이브러리를 참조함
5. example의 aes ccm 참고


# CMSIS Configuration Wizard Embedded Studio 적용 및 편집
1. Tools > ⚙️ options > Building > Global Macros 이동 후 매크로 추가
CMSIS_CONFIG_TOOL=$(SDK_PATH)/external_tools/cmsisconfig/CMSIS_Configuration_Wizard.jar
2. File > Open Studio Folder... > Extenal Tools Configuration 을 클릭하면 편집창에 tools.xml 파일이 열립니다. 하단 </item> </if> 사이에 아래 코드를 복사 한뒤 붙여넣기를 해주시면 됩니다.
<item name="Tool.CMSIS_Config_Wizard" wait="no">

    <menu>&amp;CMSIS Configuration Wizard</menu>

    <text>CMSIS Configuration Wizard</text>

    <tip>Open a configuration file in CMSIS Configuration Wizard</tip>

    <key>Ctrl+Y</key>

    <match>*config*.h</match>

    <message>CMSIS Config</message>

    <commands>

      java -jar &quot;$(CMSIS_CONFIG_TOOL)&quot; &quot;$(InputPath)&quot;

    </commands>

</item>