# Authenticator


## Running tests

```bash
mvn clean test \
    -Dcredentials.rest-arachne.username=user \
    -Dcredentials.rest-arachne.password=password \
    -Dcredentials.rest-atlas.username=user \ 
    -Dcredentials.rest-atlas.password=password \
    -Dwebdriver.chrome.driver=/chromedriver.exe \
    -Dauthenticator.methods.github.config.apiKey=abc123 \
    -Dauthenticator.methods.github.config.apiSecret=def567 \
    -Dcredentials.github.username=user \
    -Dcredentials.github.password
```
