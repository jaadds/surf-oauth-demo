/*
 *
 *   Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * /
 */

package nl.surfnet.demo;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.httpclient.params.HttpParams;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.AccessTokenInfo;
import org.wso2.carbon.apimgt.api.model.AccessTokenRequest;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.api.model.OAuthAppRequest;
import org.wso2.carbon.apimgt.api.model.OAuthApplicationInfo;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.wso2.carbon.apimgt.keymgt.AbstractKeyManager;

import javax.xml.stream.XMLStreamException;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class provides the implementation to use "Apis" {@link "https://github.com/OAuth-Apis/apis"} for managing
 * OAuth clients and Tokens needed by WSO2 API Manager.
 */
public class SurfOAuthClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(SurfOAuthClient.class);

    // We need to maintain a mapping between Consumer Key and id. To get details of a specific client,
    // we need to call client registration endpoint using id.
    Map<String, Long> nameIdMapping = new HashMap<String, Long>();

    private KeyManagerConfiguration configuration;

    /**
     * {@code APIManagerComponent} calls this method, passing KeyManagerConfiguration as a {@code String}.
     *
     * @param configuration Configuration as a {@link org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration}
     */
    @Override
    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {

        this.configuration = configuration;
    }

    /**
     * This method will Register the client in Authorization Server.
     *
     * @param oauthAppRequest this object holds all parameters required to register an OAuth Client.
     */
    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = oauthAppRequest.getOAuthApplicationInfo();

        log.debug("Creating a new oAuthApp in Authorization Server");

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

        // Getting Client Registration Url and Access Token from Config.
        String registrationEndpoint = config.getParameter(SurfClientConstants.CLIENT_REG_ENDPOINT);
        String registrationToken = config.getParameter(SurfClientConstants.REGISTRAION_ACCESS_TOKEN);

        HttpPut httpPut = new HttpPut(registrationEndpoint.trim());

        HttpClient httpClient = getHttpClient();

        BufferedReader reader = null;
        try {
            //Create the JSON Payload that should be sent to OAuth Server.
            String jsonPayload = createJsonPayloadFromOauthApplication(oAuthApplicationInfo);

            log.debug("Payload for creating new client : " + jsonPayload);

            httpPut.setEntity(new StringEntity(jsonPayload, SurfClientConstants.UTF_8));
            httpPut.setHeader(SurfClientConstants.CONTENT_TYPE, SurfClientConstants.APPLICATION_JSON_CONTENT_TYPE);

            // Setting Authorization Header, with Access Token
            httpPut.setHeader(SurfClientConstants.AUTHORIZATION, SurfClientConstants.BEARER + registrationToken);

            HttpResponse response = httpClient.execute(httpPut);
            int responseCode = response.getStatusLine().getStatusCode();

            JSONObject parsedObject;
            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), SurfClientConstants.UTF_8));

            // If successful a 201 will be returned.
            if (HttpStatus.SC_CREATED == responseCode) {

                parsedObject = getParsedObjectByReader(reader);
                if (parsedObject != null) {
                    oAuthApplicationInfo = createOAuthAppfromResponse(parsedObject);

                    // We need the id when retrieving a single OAuth Client. So we have to maintain a mapping
                    // between the consumer key and the ID.
                    nameIdMapping.put(oAuthApplicationInfo.getClientId(), (Long) oAuthApplicationInfo.getParameter
                            ("id"));

                    return oAuthApplicationInfo;
                }
            } else {
                handleException("Some thing wrong here while registering the new client " +
                                "HTTP Error response code is " + responseCode);
            }

        } catch (UnsupportedEncodingException e) {
            handleException("Encoding for the Response not-supported.", e);
        } catch (ParseException e) {
            handleException("Error while parsing response json", e);
        } catch (IOException e) {
            handleException("Error while reading response body ", e);
        } finally {
            //close buffer reader.
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            httpClient.getConnectionManager().shutdown();
        }
        return null;
    }

    /**
     * This method will update an existing OAuth Client.
     *
     * @param oauthAppRequest Parameters to be passed to Authorization Server,
     *                        encapsulated as an {@code OAuthAppRequest}
     * @return Details of updated OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {

        log.debug("Updating OAuth Client..");

        // We have to send the id with the update request.
        String consumerKey = oauthAppRequest.getOAuthApplicationInfo().getClientId();

        Long id = nameIdMapping.get(consumerKey);

        if (id == null) {
            return oauthAppRequest.getOAuthApplicationInfo();
        }

        String registrationUrl = configuration.getParameter(SurfClientConstants.CLIENT_REG_ENDPOINT);
        String accessToken = configuration.getParameter(SurfClientConstants.REGISTRAION_ACCESS_TOKEN);
        BufferedReader reader = null;
        oauthAppRequest.getOAuthApplicationInfo().addParameter("id", id);

        registrationUrl += "/" + id.toString();

        HttpClient client = getHttpClient();
        try {
            String jsonPayload = createJsonPayloadFromOauthApplication(oauthAppRequest.getOAuthApplicationInfo());

            log.debug("JSON Payload for update method : " + jsonPayload);

            HttpPost httpPost = new HttpPost(registrationUrl);
            httpPost.setEntity(new StringEntity(jsonPayload, "UTF8"));
            httpPost.setHeader(SurfClientConstants.CONTENT_TYPE, SurfClientConstants.APPLICATION_JSON_CONTENT_TYPE);
            httpPost.setHeader(SurfClientConstants.AUTHORIZATION, SurfClientConstants.BEARER + accessToken);
            HttpResponse response = client.execute(httpPost);

            int responseCode = response.getStatusLine().getStatusCode();

            log.debug("Response Code from Server: " + responseCode);

            JSONObject parsedObject;

            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), SurfClientConstants.UTF_8));

            if (responseCode == HttpStatus.SC_CREATED || responseCode == HttpStatus.SC_OK) {
                parsedObject = getParsedObjectByReader(reader);
                if (parsedObject != null) {
                    return createOAuthAppfromResponse(parsedObject);
                } else {
                    handleException("ParseObject is empty. Can not return oAuthApplicationInfo.");
                }
            } else {
                handleException("Some thing wrong here when updating the Client for key." + oauthAppRequest
                        .getOAuthApplicationInfo().getClientId() + ". Error " + "code" + responseCode);
            }

        } catch (UnsupportedEncodingException e) {
            handleException("Some thing wrong here when Updating a Client for key " + oauthAppRequest
                    .getOAuthApplicationInfo().getClientId(), e);
        } catch (ParseException e) {
            handleException("Error while parsing response json", e);
        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        } finally {
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            client.getConnectionManager().shutdown();
        }
        return null;
    }

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param consumerKey consumer key of the OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public void deleteApplication(String consumerKey) throws APIManagementException {

        log.debug("Creating a new OAuth Client in Authorization Server..");

        Long id = nameIdMapping.get(consumerKey);

        String configURL = configuration.getParameter(SurfClientConstants.CLIENT_REG_ENDPOINT);
        String configURLsAccessToken = configuration.getParameter(SurfClientConstants.REGISTRAION_ACCESS_TOKEN);
        HttpClient client = getHttpClient();

        try {

            // Deletion has to be called providing the ID. If we don't have the ID we can't proceed with Delete.
            if (id != null) {
                configURL += "/" + id.toString();
                HttpDelete httpDelete = new HttpDelete(configURL);

                // Set Authorization Header
                httpDelete.addHeader(SurfClientConstants.AUTHORIZATION, SurfClientConstants.BEARER + configURLsAccessToken);
                HttpResponse response = client.execute(httpDelete);
                int responseCode = response.getStatusLine().getStatusCode();
                if (log.isDebugEnabled()) {
                    log.debug("Delete application response code :  " + responseCode);
                }
                if (responseCode == HttpStatus.SC_OK ||
                    responseCode == HttpStatus.SC_NO_CONTENT) {
                    log.info("OAuth Client for consumer Id " + consumerKey + " has been successfully deleted");
                    nameIdMapping.remove(consumerKey);
                } else {
                    handleException("Problem occurred while deleting client for Consumer Key " + consumerKey);
                }
            }

        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        } finally {
            client.getConnectionManager().shutdown();
        }
    }

    /**
     * This method retrieves OAuth application details by given consumer key.
     *
     * @param consumerKey consumer key of the OAuth Client.
     * @return an {@code OAuthApplicationInfo} having all the details of an OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {

        HttpClient client = getHttpClient();

        // First get the Id corresponding to consumerKey
        Long id = nameIdMapping.get(consumerKey);
        String registrationURL = configuration.getParameter(SurfClientConstants.CLIENT_REG_ENDPOINT);
        String accessToken = configuration.getParameter(SurfClientConstants.REGISTRAION_ACCESS_TOKEN);
        BufferedReader reader = null;

        try {

            if (id != null) {
                // To get the specific client, we have to call like
                // http://192.168.52.5:8080/admin/resourceServer/251/client/355
                log.debug("Found id : " + id.toString() + " for consumer key :" + consumerKey);
                registrationURL += "/" + id.toString();
            }

            HttpGet request = new HttpGet(registrationURL);
            //set authorization header.
            request.addHeader(SurfClientConstants.AUTHORIZATION, SurfClientConstants.BEARER + accessToken);
            HttpResponse response = client.execute(request);

            int responseCode = response.getStatusLine().getStatusCode();
            Object parsedObject;

            HttpEntity entity = response.getEntity();

            reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));

            if (responseCode == HttpStatus.SC_CREATED || responseCode == HttpStatus.SC_OK) {
                JSONParser parser = new JSONParser();
                if (reader != null) {
                    parsedObject = parser.parse(reader);

                    // If we have appended the ID, then the response is a JSONObject if not the response is a JSONArray.
                    if (parsedObject instanceof JSONArray) {
                        // If the response is a JSONArray, then we prime the nameId map,
                        // with the response received. And then return details of the specific client.
                        addToNameIdMap((JSONArray) parsedObject);
                        for (Object object : (JSONArray) parsedObject) {
                            JSONObject jsonObject = (JSONObject) object;
                            if ((jsonObject.get(SurfClientConstants.CLIENT_ID)).equals
                                    (consumerKey)) {
                                return createOAuthAppfromResponse(jsonObject);
                            }
                        }
                    } else {
                        return createOAuthAppfromResponse((JSONObject) parsedObject);
                    }
                }

            } else {
                handleException("Something went wrong while retrieving client for consumer key " + consumerKey);
            }

        } catch (ParseException e) {
            handleException("Error while parsing response json.", e);
        } catch (IOException e) {
            handleException("Error while reading response body.", e);
        } finally {
            client.getConnectionManager().shutdown();
            IOUtils.closeQuietly(reader);
        }

        return null;
    }

    @Override
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(OAuthApplicationInfo oAuthApplication,
                                                                  AccessTokenRequest tokenRequest)
            throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {

        return null;
    }

    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {
        AccessTokenInfo tokenInfo = new AccessTokenInfo();

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

        String introspectionURL = config.getParameter(SurfClientConstants.INTROSPECTION_URL);
        String introspectionConsumerKey = config.getParameter(SurfClientConstants.INTROSPECTION_CK);
        String introspectionConsumerSecret = config.getParameter(SurfClientConstants.INTROSPECTION_CS);
        String encodedSecret = Base64.encode(new String(introspectionConsumerKey + ":" + introspectionConsumerSecret)
                                                     .getBytes());

        BufferedReader reader = null;

        try {
            URIBuilder uriBuilder = new URIBuilder(introspectionURL);
            uriBuilder.addParameter("access_token", accessToken);
            uriBuilder.build();

            HttpGet httpGet = new HttpGet(uriBuilder.build());
            HttpClient client = new DefaultHttpClient();

            httpGet.setHeader("Authorization", "Basic " + encodedSecret);
            HttpResponse response = client.execute(httpGet);
            int responseCode = response.getStatusLine().getStatusCode();

            if (log.isDebugEnabled()) {
                log.debug("HTTP Response code : " + responseCode);
            }

            // {"audience":"MappedClient","scopes":["test"],"principal":{"name":"mappedclient","roles":[],"groups":[],"adminPrincipal":false,
            // "attributes":{}},"expires_in":1433059160531}
            HttpEntity entity = response.getEntity();
            JSONObject parsedObject;
            String errorMessage = null;
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), "UTF-8"));

            if (HttpStatus.SC_OK == responseCode) {
                //pass bufferReader object  and get read it and retrieve  the parsedJson object
                parsedObject = getParsedObjectByReader(reader);
                if (parsedObject != null) {

                    Map valueMap = parsedObject;
                    Object principal = valueMap.get("principal");

                    if (principal == null) {
                        tokenInfo.setTokenValid(false);
                        return tokenInfo;
                    }
                    Map principalMap = (Map) principal;
                    String clientId = (String) principalMap.get("name");
                    Long expiryTimeString = (Long) valueMap.get("expires_in");

                    // Returning false if mandatory attributes are missing.
                    if (clientId == null || expiryTimeString == null) {
                        tokenInfo.setTokenValid(false);
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_EXPIRED);
                        return tokenInfo;
                    }

                    long currentTime = System.currentTimeMillis();
                    long expiryTime = expiryTimeString;
                    if (expiryTime > currentTime) {
                        tokenInfo.setTokenValid(true);
                        tokenInfo.setConsumerKey(clientId);
                        tokenInfo.setValidityPeriod(expiryTime - currentTime);
                        // Considering Current Time as the issued time.
                        tokenInfo.setIssuedTime(currentTime);
                        JSONArray scopesArray = (JSONArray) valueMap.get("scopes");

                        if (scopesArray != null && !scopesArray.isEmpty()) {

                            String[] scopes = new String[scopesArray.size()];
                            for (int i = 0; i < scopes.length; i++) {
                                scopes[i] = (String) scopesArray.get(i);
                            }
                            tokenInfo.setScope(scopes);
                        }
                    } else {
                        tokenInfo.setTokenValid(false);
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                        return tokenInfo;
                    }

                } else {
                    log.error("Invalid Token " + accessToken);
                    tokenInfo.setTokenValid(false);
                    tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                    return tokenInfo;
                }
            }//for other HTTP error codes we just pass generic message.
            else {
                log.error("Invalid Token " + accessToken);
                tokenInfo.setTokenValid(false);
                tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                return tokenInfo;
            }

        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException("HTTP request error has occurred while sending request  to OAuth Provider. " +
                            e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } catch (URISyntaxException e) {
            handleException("Error occurred while building URL with params." + e.getMessage(), e);
        } catch (ParseException e) {
            handleException("Error while parsing response json " + e.getMessage(), e);
        } finally {
            IOUtils.closeQuietly(reader);
        }

        return tokenInfo;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String jsonInput) throws APIManagementException {
        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with Application in API Manager
     *
     * @param appInfoRequest Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest appInfoRequest)
            throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = appInfoRequest.getOAuthApplicationInfo();
        return oAuthApplicationInfo;
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    /**
     * This method can be used to create a JSON Payload out of the Parameters defined in an OAuth Application.
     *
     * @param oAuthApplicationInfo Object that needs to be converted.
     * @return
     */
    private String createJsonPayloadFromOauthApplication(OAuthApplicationInfo oAuthApplicationInfo)
            throws APIManagementException {

        Map<String, Object> paramMap = new HashMap<String, Object>();

        if (oAuthApplicationInfo.getClientName() == null ||
            oAuthApplicationInfo.getParameter(SurfClientConstants.CLIENT_CONTACT_NAME) == null ||
            oAuthApplicationInfo.getParameter(SurfClientConstants.CLIENT_SCOPE) == null ||
            oAuthApplicationInfo.getParameter(SurfClientConstants.CLIENT_CONTAT_EMAIL) == null) {
            throw new APIManagementException("Mandatory parameters missing");
        }

        // Format of the request needed.
        // {"name":"TestClient_1","scopes":["scope1"],
        // "contactName":"John Doe",
        // "contactEmail":"john@doe.com"}

        paramMap.put(SurfClientConstants.CLIENT_NAME, oAuthApplicationInfo.getClientName());

        JSONArray scopes = (JSONArray) oAuthApplicationInfo.getParameter(SurfClientConstants.CLIENT_SCOPE);
        paramMap.put("scopes", scopes);

        paramMap.put(SurfClientConstants.CLIENT_CONTACT_NAME, oAuthApplicationInfo.getParameter(SurfClientConstants
                                                                                                        .CLIENT_CONTACT_NAME));
        paramMap.put(SurfClientConstants.CLIENT_CONTAT_EMAIL, oAuthApplicationInfo.getParameter(SurfClientConstants
                                                                                                        .CLIENT_CONTAT_EMAIL));
        if (oAuthApplicationInfo.getParameter("id") != null) {
            paramMap.put("id", oAuthApplicationInfo.getParameter("id"));
        }

        return JSONObject.toJSONString(paramMap);
    }


    /**
     * Can be used to parse {@code BufferedReader} object that are taken from response stream, to a {@code JSONObject}.
     *
     * @param reader {@code BufferedReader} object from response.
     * @return JSON payload as a name value map.
     */
    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {

        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);
        }
        return parsedObject;
    }

    /**
     * common method to throw exceptions.
     *
     * @param msg this parameter contain error message that we need to throw.
     * @param e   Exception object.
     * @throws APIManagementException
     */
    private void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    /**
     * common method to throw exceptions. This will only expect one parameter.
     *
     * @param msg error message as a string.
     * @throws APIManagementException
     */
    private void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     * This method will create {@code OAuthApplicationInfo} object from a Map of Attributes.
     *
     * @param responseMap Response returned from server as a Map
     * @return OAuthApplicationInfo object will return.
     */
    private OAuthApplicationInfo createOAuthAppfromResponse(Map responseMap) {


        // Sample response returned by client registration endpoint.
        // {"id":305,"creationDate":1430486098086,"modificationDate":1430486098086,"name":"TestClient_2",
        // "clientId":"testclient_2","secret":"3b4dbfb6-0ad9-403e-8ed6-715459fc8c78",
        // "description":null,"contactName":"John Doe","contactEmail":"john@doe.com",
        // "scopes":["scope1"],"attributes":{},"thumbNailUrl":null,"redirectUris":[],
        // "skipConsent":false,"includePrincipal":false,"expireDuration":0,"useRefreshTokens":false,
        // "allowedImplicitGrant":false,"allowedClientCredentials":false}

        OAuthApplicationInfo info = new OAuthApplicationInfo();
        Object clientId = responseMap.get(SurfClientConstants.CLIENT_ID);
        info.setClientId((String) clientId);

        Object clientSecret = responseMap.get(SurfClientConstants.CLIENT_SECRET);
        info.setClientSecret((String) clientSecret);

        Object id = responseMap.get("id");
        info.addParameter("id", id);

        Object contactName = responseMap.get(SurfClientConstants.CLIENT_CONTACT_NAME);
        if (contactName != null) {
            info.addParameter("contactName", contactName);
        }

        Object contactMail = responseMap.get(SurfClientConstants.CLIENT_CONTAT_EMAIL);
        if (contactMail != null) {
            info.addParameter("contactMail", contactMail);
        }

        Object scopes = responseMap.get(SurfClientConstants.SCOPES);
        if (scopes != null) {
            info.addParameter("scopes", scopes);
        }

        return info;
    }

    /**
     * This method will return HttpClient object.
     *
     * @return HttpClient object.
     */
    private HttpClient getHttpClient() {
        HttpClient httpClient = new DefaultHttpClient();
        return httpClient;
    }

    private void addToNameIdMap(JSONArray clientArray) {
        for (Object jsonObject : clientArray) {
            if (jsonObject instanceof JSONObject) {
                Long id = (Long) ((JSONObject) jsonObject).get("id");
                String consumerId = (String) ((JSONObject) jsonObject).get(SurfClientConstants.CLIENT_ID);
                nameIdMapping.put(consumerId, id);
            }
        }
    }
}
