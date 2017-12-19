# WS-Federation for keycloak

* Currently working on 3.4.1.Final

## Install

This is an example with keycloak avaible at /opt/keycloak

```Bash
#Create layer in keycloak setup
install -d -v -m755 /opt/keycloak/modules/system/layers/wsfed -o keycloak -g keycloak

#Setup the module directory
install -d -v -m755 /opt/keycloak/modules/system/layers/wsfed/com/quest/keycloak-wsfed/main/ -o keycloak -g keycloak

#Install jar
install -v -m0755 -o keycloak -g keycloak -D target/keycloak-wsfed-3.4.0.Final.jar /opt/keycloak/modules/system/layers/wsfed/com/quest/keycloak-wsfed/main/

#Install module file
install -v -m0755 -o keycloak -g keycloak -D module.xml /opt/keycloak/modules/system/layers/wsfed/com/quest/keycloak-wsfed/main/

```

## Enable zone

__layers.conf__

```Bash
layers=keycloak,wsfed
```

## Enable module & load theme

__standalone.xml__

```xml
<web-context>auth</web-context>
<providers>
    <provider>module:com.quest.keycloak-wsfed</provider>
    ...
</providers>
...
<theme>
    <modules>
            <module>
                    com.quest.keycloak-wsfed
            </module>
    </modules>
    ...
</theme>
...
```

After that you need to set the Admin Console theme to wsfed then restart keycloak.
