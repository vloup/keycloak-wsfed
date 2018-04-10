# WS-Federation for Keycloak

The purpose of this module is to support the 
[WS-FED protocol](http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html) 
in [Keycloak](https://www.keycloak.org/). Only Web (Passive) requestors are supported, as defined in 
[section 13 of the specification](http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html#_Toc223175002).
However, in this capacity the WS-Fed protocol can be used for communication with:

* Keycloak clients (WS Resources), with Keycloak acting as an IdP/STS.
* Other IdPs, with Keycloak acting as an Identity Broker.

The WS-Fed protocol does not specify the format of the tokens, but this module supports SAML 2.0, SAML 1.1 and JWT 
tokens for its operations. 

This module is currently working on 3.4.3.Final (check tags for compatibility with previous keycloak versions)

## How to Install

### Copy files

This is an example with keycloak available at /opt/keycloak

```Bash
#Create layer in keycloak setup
install -d -v -m755 /opt/keycloak/modules/system/layers/wsfed -o keycloak -g keycloak

#Setup the module directory
install -d -v -m755 /opt/keycloak/modules/system/layers/wsfed/com/quest/keycloak-wsfed/main/ -o keycloak -g keycloak

#Install jar
install -v -m0755 -o keycloak -g keycloak -D target/keycloak-wsfed-3.4.3.Final.jar /opt/keycloak/modules/system/layers/wsfed/com/quest/keycloak-wsfed/main/

#Install module file
install -v -m0755 -o keycloak -g keycloak -D module.xml /opt/keycloak/modules/system/layers/wsfed/com/quest/keycloak-wsfed/main/

```

### Enable module & load theme

__layers.conf__

```Bash
layers=keycloak,wsfed
```

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

After that you need to set the Admin Console theme to `wsfed` in the master realm and in the realm with the WS-FED 
clients, then restart keycloak.

## How to use

### How to setup a Keycloak client

### How to setup a Keycloak identity broker.

We will explain here how to setup identity brokering using two instances of keycloak: one as identity broker, and the 
second as external IdP. Naturally, for this to work, the WS-Fed module must be installed on both instances of Keycloak.

#### Setting up the identity broker

Go to the `Identity Providers` menu item and create a new identity provider selecting `WS-Fed` from the list.

The first part of the settings are the general IdP settings, described in the 
[keycloak documentation](https://www.keycloak.org/docs/latest/server_admin/index.html#_general-idp-config). The only 
things of note are that:
 
 * The **alias** can be set to any value, it serves as the identifier of the identity broker -  external IdP link.
 * The **First Login Flow** should be set to `first broker login` in most cases. This means that keycloak will create
 a local registration of any external users at first login, create a link between the local and external user for 
 subsequent logins.
 
The endpoint information from the external IdP must be setup in the `WS-Fed configuration` section. For a Keycloak 
external IdP, this can be obtained at the address:
 
 ```
 http[s]://{host:port}/auth/realms/{realm-name}/protocol/wsfed/descriptor
 ```
 
This will give the following information:
 
 * **Single Sign-On Service URL** (in the `PassiveRequestorEndpoint` section)
 * **Single Logout Service URL** (in the `PassiveRequestorEndpoint` section, the same as the Single Sign-On Service URL)
 * **Validating X509 Certificates** (in the `X509Certificate` tags). This is only use if the **Validate Signature** 
 option is set to on (which is recommended).
 
The remaining options are:
  
 * **WS-Fed Realm**: This is the name of the client in the keycloak external IdP. The value is unimportant as long 
 as it is the same in both the configuration of the identity broker and the external IdP.
 * **Backchannel Logout**: set to "on" if the external IdP supports the Backchannel logout
 * **Handle Empty Action as wsignoutcleanup1.0**: normally for the clean-up phase of a sign-out, the `wa` action 
 must be set to wsignoutcleanup1.0, but with this option activated, an empty `wa` will be considered as a cleanup. 
 
#### Setting up the client (WS Resource)
 
On the external IdP keycloak, go to the `Clients` menu item and create a new client, selecting `wsfed` for the **Client
Protocol**. The **Client ID** value must be set to the same value as in the **WS-Fed Realm** value on the Keycloak 
identity broker. 

In the `Settings` tab, the only important elements to set are:

* the **SAML Assertion Token Format**, which specifies the type of token to use. Currently only SAML 1.1 and 2.0 tokens
are supported.
WS-Fed identity brokers. 
* the **Valid Redirect URIs** parameter. For a Keyclock identity broker, this value MUST be set to the value of the 
**Redirect URI** in the settings tab.

##### Using mappers to automatically get first broker login information

If no mappers are setup, upon the first login using Keycloak as an identity broker, and after authentication with the 
external IdP is successful, Keycloak will display a form to get the missing information. The information required will
be: **username**, **email**, **first name** and **last name**. The username will always be set, as keycloak requires
this information and will use the subject information if necessary, but it is possible to modify it.

However, it is also possible to set this information by passing the information as attributes in the SAML assertion. If
all information is provided, Keycloak will skip the form, and directly create the user. Currently however, this only
works with SAML 1.1 assertions. 

To get the information, the following mappers must be created in the client:

* A mapper for the username: Should be of type `SAML User Property`. The **property** should be set to `username`. The 
**SAML Attribute Name** MUST be set to `name`.
* A mapper for the email:  Should be of type `SAML User Property`. The **property** should be set to `email`. The 
**SAML Attribute Name** MUST be set to `emailaddress`.
* A mapper for the first name:  Should be of type `SAML User Property`. The **property** should be set to `firstName`. The 
**SAML Attribute Name** MUST be set to `givenname`.
* A mapper for the last name:  Should be of type `SAML User Property`. The **property** should be set to `lastName`. The 
**SAML Attribute Name** MUST be set to `surname`.