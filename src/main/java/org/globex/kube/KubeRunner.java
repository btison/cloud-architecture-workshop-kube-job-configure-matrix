package org.globex.kube;

import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.api.model.apps.Deployment;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.Resource;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.ArrayUtils;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.resteasy.reactive.ClientWebApplicationException;
import org.jboss.resteasy.reactive.common.jaxrs.ResponseImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

@ApplicationScoped
public class KubeRunner {

    private static final Logger LOGGER = LoggerFactory.getLogger(KubeRunner.class);

    @Inject
    KubernetesClient client;

    @RestClient
    SynapseService synapseService;

    @RestClient
    MatrixClientService matrixService;

    private static final String HmacAlgorithm = "HmacSHA1";

    public int run() {

        // mandatory environment variables
        String namespace = System.getenv("NAMESPACE");
        if (namespace == null || namespace.isBlank()) {
            LOGGER.error("Environment variable 'NAMESPACE' for namespace not set. Exiting...");
            return -1;
        }

        String numUsersStr = System.getenv("NUM_USERS");
        if (numUsersStr == null || numUsersStr.isBlank()) {
            LOGGER.error("Environment variable 'NUM_USERS' not set. Exiting...");
            return -1;
        }
        int numUsers = Integer.parseInt(numUsersStr);

        // make sure matrix is available
        String deploymentName = System.getenv().getOrDefault("SYNAPSE_DEPLOYMENT", "matrix-synapse");

        String maxTimeToWaitStr = System.getenv().getOrDefault("MAX_TIME_TO_WAIT_MS", "60000");
        long maxTimeToWait = Long.parseLong(maxTimeToWaitStr);

        Resource<Deployment> deployment = client.apps().deployments().inNamespace(namespace).withName(deploymentName);
        try {
            deployment.waitUntilCondition(d -> d != null && Objects.equals(d.getStatus().getAvailableReplicas(), d.getStatus().getReadyReplicas()),
                    maxTimeToWait, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            LOGGER.error("Deployment " + deploymentName + " is not ready after " + maxTimeToWaitStr + " milliseconds. Exiting...");
            return -1;
        }
        if (deployment.get() == null) {
            LOGGER.error("Deployment " + deploymentName + " is not ready after " + maxTimeToWaitStr + " milliseconds. Exiting...");
            return -1;
        }

        // read shared registration secret
        String secretName = System.getenv().getOrDefault("SYNAPSE_SECRET", "matrix-synapse-config");
        String registrationSecretKey = System.getenv().getOrDefault("SYNAPSE_SECRET_REGISTRATION_SECRET_KEY", "registration-secret");

        Resource<Secret> secret = client.secrets().inNamespace(namespace).withName(secretName);
        if (secret.get() == null) {
            LOGGER.error("Secret " + secretName + " not found in namespace " + namespace + ". Exiting...");
            return -1;
        }
        String registrationSecret = secret.get().getData().get(registrationSecretKey);
        if (registrationSecret == null || registrationSecret.isBlank()) {
            LOGGER.error("Key" + registrationSecretKey + " not found in secret " + secretName + ". Exiting...");
            return -1;
        }

        //Register admin user
        boolean errorFlag = false;
        boolean adminExists = false;
        String accessToken = "";
        String adminUsername = System.getenv().getOrDefault("SYNAPSE_ADMIN_USER", "synapseadmin");
        String adminPassword = System.getenv().getOrDefault("SYNAPSE_ADMIN_PASSWORD", "synapseadminadmin");
        String nonce;
        try {
            nonce = getRegistrationNonce();
        } catch (ClientWebApplicationException e) {
            LOGGER.error("Error obtaining registration nonce", e);
            throw e;
        }
        byte[] nullArray = {0x00};
        byte[] hmacData = ArrayUtils.addAll(nonce.getBytes(StandardCharsets.UTF_8),
                ArrayUtils.addAll(nullArray, ArrayUtils.addAll(adminUsername.getBytes(StandardCharsets.UTF_8),
                        ArrayUtils.addAll(nullArray, ArrayUtils.addAll(adminPassword.getBytes(StandardCharsets.UTF_8),
                                ArrayUtils.addAll(nullArray, "admin".getBytes(StandardCharsets.UTF_8)))))));
        byte[] sharedSecret = Base64.getDecoder().decode(registrationSecret.getBytes(StandardCharsets.UTF_8));
        String hmac = generateMac(sharedSecret, hmacData);
        JsonObject registerAdminUser = new JsonObject().put("nonce", nonce).put("username", adminUsername)
                .put("password", adminPassword).put("admin", true).put("mac", hmac);
        try {
            Response response = synapseService.registerUser(registerAdminUser.encode());
            LOGGER.info("User " + adminUsername + " created");
            accessToken = new JsonObject(getEntity(response)).getString("access_token");
        } catch (WebApplicationException e) {
            Response response = e.getResponse();
            if (response.getStatus() == 400) {
                JsonObject error = new JsonObject(getEntity(response));
                if ("M_USER_IN_USE".equals(error.getString("errcode"))) {
                    LOGGER.warn("Admin User is already registered");
                    adminExists = true;
                } else {
                    errorFlag = true;
                }
            }
        }
        if (errorFlag) {
            LOGGER.error("Exception while registering admin user. Exiting...");
            return -1;
        }

        // login as admin
        if (adminExists) {
            JsonObject loginAsAdminPayload = new JsonObject().put("type", "m.login.password").put("user", adminUsername)
                    .put("password", adminPassword);
            try {
                Response response = matrixService.login(loginAsAdminPayload.encode());
                accessToken = new JsonObject(getEntity(response)).getString("access_token");
            } catch (WebApplicationException e) {
                LOGGER.error("Exception while logging in as admin user. Exiting...");
            }
        }

        // create users
        String userPrefix = System.getenv().getOrDefault("USER_PREFIX", "user");
        String userPassword = System.getenv().getOrDefault("USER_PASSWORD", "openshift");
        String serverName = System.getenv().getOrDefault("SYNAPSE_SERVER_NAME", "globex");

        String numUserStart = System.getenv().getOrDefault("NUM_USERS_START", "1");
        int numUsersStart = Integer.parseInt(numUserStart);

        for (int i = numUsersStart; i <= numUsers; i++) {
            String user = userPrefix + i;
            JsonObject creatUserPayload = new JsonObject().put("password", userPassword).put("admin", false)
                    .put("deactivated", false).put("user_type", null);
            try {
                synapseService.createUser(creatUserPayload.encode(), "@" + user + ":" + serverName, "Bearer " + accessToken);
            } catch (WebApplicationException e) {
                errorFlag = true;
                break;
            }
        }
        if (errorFlag) {
            LOGGER.error("Exception while creating users. Exiting...");
            return -1;
        }

        // create secret for admin accesstoken
        String synapseTokenSecret = System.getenv().getOrDefault("SYNAPSE_TOKEN_SECRET", "matrix-synapse-token");
        String synapseTokenSecretKey = System.getenv().getOrDefault("SYNAPSE_TOKEN_SECRET_KEY", "access_token");
        Secret tokenSecret = client.secrets().inNamespace(namespace).withName(synapseTokenSecret).get();
        if (tokenSecret != null) {
            LOGGER.warn("Secret " + synapseTokenSecret + " already exists");
        }
        Secret newSecret = new SecretBuilder().withNewMetadata().withName(synapseTokenSecret).endMetadata()
                .addToData(synapseTokenSecretKey, Base64.getEncoder().encodeToString(accessToken.getBytes(StandardCharsets.UTF_8))).build();
        client.secrets().inNamespace(namespace).resource(newSecret).serverSideApply();
        LOGGER.info("Token secret created");

        return 0;
    }


    private String getRegistrationNonce() {
        try {
            Response response = synapseService.register();
            return new JsonObject(getEntity(response)).getString("nonce");
        } catch (ClientWebApplicationException e) {
            LOGGER.error("Error obtaining registration nonce", e);
            throw e;
        }
    }

    private String generateMac(byte[] key, byte[] data) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, HmacAlgorithm);
            Mac mac = Mac.getInstance(HmacAlgorithm);
            mac.init(secretKeySpec);
            return bytesToHex(mac.doFinal(data));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }

    public static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte h : hash) {
            String hex = Integer.toHexString(0xff & h);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private String getEntity(Response response) {
        ResponseImpl responseImpl = (ResponseImpl) response;
        InputStream is = responseImpl.getEntityStream();
        if (is != null) {
            try {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return "{}";
    }

}
