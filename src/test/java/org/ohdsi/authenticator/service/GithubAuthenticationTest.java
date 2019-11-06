package org.ohdsi.authenticator.service;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.fluentlenium.adapter.junit.FluentTest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ohdsi.authenticator.exception.AuthenticationException;
import org.ohdsi.authenticator.model.UserInfo;
import org.ohdsi.authenticator.service.authentication.Authenticator;
import org.ohdsi.authenticator.service.github.RedirectRequiredException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.pac4j.core.credentials.TokenCredentials;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.Assert;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@SpringBootTest
@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = "test")
public class GithubAuthenticationTest extends FluentTest {

    @Value("${webdriver.chrome.driver}")
    private String driverPath;

    @Value("${credentials.github.username}")
    private String username;

    @Value("${credentials.github.password}")
    private String passwordHex;

    @Autowired
    protected Authenticator authenticator;

    @Override
    public WebDriver newWebDriver() {

        System.setProperty("webdriver.chrome.driver", driverPath);
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless");
        options.addArguments("--incognito");
        return new ChromeDriver(options);
    }

    @Test
    public void testAuthSuccess() throws DecoderException, URISyntaxException {

        String authUrl = null;

        try {
            authenticator.authenticate("github", new TokenCredentials(null));
        } catch (RedirectRequiredException ex) {
            authUrl = ex.getRedirectUrl();
        }

        Assert.isTrue(Objects.nonNull(authUrl), "Failed to generate Authorization Url");

        goTo(authUrl);

        $("#login_field").fill().with(username);
        $("#password").fill().with(new String(Hex.decodeHex(passwordHex)));
        $("[type=submit]").submit();
        await().atMost(10, TimeUnit.SECONDS).untilPage().isLoaded();

        if ($(".oauth-user-permissions").size() > 0) {
            $("#js-oauth-authorize-btn").click();
            await().atMost(10, TimeUnit.SECONDS).untilPage().isLoaded();
        }

        URI uri = new URI(getDriver().getCurrentUrl());

        List<NameValuePair> params = URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);
        String code = params.stream()
            .filter(p -> Objects.equals(p.getName(), "code"))
            .findFirst()
            .orElseThrow(() -> new AuthenticationException("Cannot extract code"))
            .getValue();

        UserInfo userInfo = authenticator.authenticate("github", new TokenCredentials(code));

        Assert.isTrue(Objects.equals(userInfo.getUsername(), username), "User was not authenticated");

        // File scrFile = ((TakesScreenshot) getDriver()).getScreenshotAs(OutputType.FILE);
        // FileUtils.copyFile(scrFile, new File("d:\\screenshot.png"));
    }
}
