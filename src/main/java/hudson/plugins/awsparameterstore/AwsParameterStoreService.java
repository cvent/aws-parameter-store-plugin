/**
 * MIT License
 * <p>
 * Copyright (c) 2018 Rik Turnbull
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package hudson.plugins.awsparameterstore;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClient;
import com.amazonaws.services.simplesystemsmanagement.model.DescribeParametersRequest;
import com.amazonaws.services.simplesystemsmanagement.model.DescribeParametersResult;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterRequest;
import com.amazonaws.services.simplesystemsmanagement.model.GetParametersByPathRequest;
import com.amazonaws.services.simplesystemsmanagement.model.GetParametersByPathResult;
import com.amazonaws.services.simplesystemsmanagement.model.Parameter;
import com.amazonaws.services.simplesystemsmanagement.model.ParameterMetadata;
import com.amazonaws.services.simplesystemsmanagement.model.ParameterStringFilter;
import com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsHelper;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import hudson.ProxyConfiguration;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildWrapper;
import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * AWS Parameter Store client.
 *
 * @author Rik Turnbull
 */
public class AwsParameterStoreService {
    public static final String DEFAULT_REGION = "us-east-1";
    public static final String NAMING_BASENAME = "basename";
    public static final String NAMING_RELATIVE = "relative";
    public static final String NAMING_ABSOLUTE = "absolute";

    private static final Logger LOGGER = Logger.getLogger(AwsParameterStoreService.class.getName());

    private AWSSimpleSystemsManagement client;

    private String credentialsId;
    private String regionName;

    /**
     * Creates a new {@link AwsParameterStoreService}.
     *
     * @param credentialsId AWS credentials identifier
     * @param regionName    AWS region name
     */
    public AwsParameterStoreService(String credentialsId, String regionName) {
        this.credentialsId = credentialsId;
        this.regionName = StringUtils.defaultString(regionName, DEFAULT_REGION);
    }

    /**
     * Returns an {@link AWSSimpleSystemsManagement}.
     *
     * @return {@link AWSSimpleSystemsManagement} singleton using the
     *         <code>credentialsId</code> and <code>regionName</code>
     */
    private synchronized AWSSimpleSystemsManagement getAWSSimpleSystemsManagement() {
        if (client == null) {
            ClientConfiguration clientConfiguration = new ClientConfiguration();
            Jenkins jenkins = Jenkins.getInstance();
            if (jenkins != null) {
                ProxyConfiguration proxy = jenkins.proxy;
                if (proxy != null) {
                    clientConfiguration.setProxyHost(proxy.name);
                    clientConfiguration.setProxyPort(proxy.port);
                    clientConfiguration.setProxyUsername(proxy.getUserName());
                    clientConfiguration.setProxyPassword(proxy.getPassword());
                }
            }

            AmazonWebServicesCredentials credentials = getAWSCredentials(credentialsId);
            if (credentials == null) {
                client = AWSSimpleSystemsManagementClient.builder().withClientConfiguration(clientConfiguration)
                        .withRegion(regionName).build();
            } else {
                client = AWSSimpleSystemsManagementClient.builder().withCredentials(credentials)
                        .withClientConfiguration(clientConfiguration).withRegion(regionName).build();
            }
        }
        return client;
    }

    /**
     * Gets AWS credentials.
     *
     * @param credentialsId Jenkins credentials identifier
     * @return AWS credentials for <code>credentialsId</code> that can be used for
     *         AWS calls
     */
    private AmazonWebServicesCredentials getAWSCredentials(String credentialsId) {
        return AWSCredentialsHelper.getCredentials(credentialsId, Jenkins.getActiveInstance());
    }

    /**
     * Adds environment variables to <code>context</code>.
     *
     * @param context SimpleBuildWrapper context
     * @param path    hierarchy for the parameter
     * @param naming  environment variable naming: basename, relative, absolute
     */
    public void buildEnvVars(SimpleBuildWrapper.Context context, String path, String naming,
            List<Parameter> parameters) {
        if (StringUtils.isEmpty(path)) {
            buildEnvVarsWithParameters(context, parameters);
        } else {
            buildEnvVarsWithParametersByPath(context, path, naming, parameters);
        }
    }

    public List<Parameter> fetchParameters(String path, Boolean recursive, String namePrefixes, String option) {
        if (StringUtils.isEmpty(path)) {
            return fetchEnvVarsWithParameters(namePrefixes, option);
        } else {
            return fetchEnvVarsWithParametersByPath(path, recursive);
        }
    }

    private List<Parameter> fetchEnvVarsWithParameters(String namePrefixes, String option) {
        final AWSSimpleSystemsManagement client = getAWSSimpleSystemsManagement();
        final List<String> names = new ArrayList<String>();
        final List<Parameter> parameters = new ArrayList<>();

        try {
            DescribeParametersRequest describeParametersRequest = new DescribeParametersRequest().withMaxResults(1);
            if (!StringUtils.isEmpty(namePrefixes)) {
                describeParametersRequest = describeParametersRequest.withParameterFilters(new ParameterStringFilter()
                        .withKey("Name").withOption(option).withValues(namePrefixes.split(",")));
            }

            do {
                final DescribeParametersResult describeParametersResult = client
                        .describeParameters(describeParametersRequest);
                for (ParameterMetadata metadata : describeParametersResult.getParameters()) {
                    names.add(metadata.getName());
                }
                describeParametersRequest.setNextToken(describeParametersResult.getNextToken());
            } while (describeParametersRequest.getNextToken() != null);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot fetch parameters: " + e.getMessage(), e);
        }

        final GetParameterRequest getParameterRequest = new GetParameterRequest().withWithDecryption(true);
        for (String name : names) {
            getParameterRequest.setName(name);
            try {
                Parameter param = client.getParameter(getParameterRequest).getParameter();
                parameters.add(param);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Cannot fetch parameter: \"" + name + "\"", e);
            }
        }
        return parameters;
    }

    /**
     * Adds environment variables to <code>context</code> using
     * <code>describeParameters</code>.
     *
     * @param context SimpleBuildWrapper context
     */
    private void buildEnvVarsWithParameters(SimpleBuildWrapper.Context context, List<Parameter> parameters) {
        for (Parameter param : parameters) {
            try {
                context.env(toEnvironmentVariable(param.getName()), param.getValue());
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Cannot load parameter: \"" + param.getName() + "\"", e);
            }
        }
    }

    private List<Parameter> fetchEnvVarsWithParametersByPath(String path, Boolean recursive) {
        final AWSSimpleSystemsManagement client = getAWSSimpleSystemsManagement();
        List<Parameter> parameters = new ArrayList<>();

        try {
            final GetParametersByPathRequest getParametersByPathRequest = new GetParametersByPathRequest()
                    .withPath(path).withRecursive(recursive).withWithDecryption(true);
            do {
                final GetParametersByPathResult getParametersByPathResult = client
                        .getParametersByPath(getParametersByPathRequest);
                parameters.addAll(getParametersByPathResult.getParameters());
                getParametersByPathRequest.setNextToken(getParametersByPathResult.getNextToken());
            } while (getParametersByPathRequest.getNextToken() != null);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Cannot fetch parameters by path: " + e.getMessage(), e);
        }
        return parameters;
    }

    /**
     * Adds environment variables to <code>context</code> using
     * <code>getParametersByPath</code>.
     *
     * @param context SimpleBuildWrapper context
     * @param path    hierarchy for the parameter
     * @param naming  environment variable naming: basename, relative, absolute
     */
    private void buildEnvVarsWithParametersByPath(SimpleBuildWrapper.Context context, String path, String naming,
            List<Parameter> parameters) {
        for (Parameter parameter : parameters) {
            try {
                context.env(toEnvironmentVariable(parameter.getName(), path, naming), parameter.getValue());
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Cannot add parameter to environment: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Converts <code>name</code> to uppercase. All non alphanumeric characters are
     * converted to underscores.
     *
     * @param name parameter name
     */
    private String toEnvironmentVariable(String name) {
        return toEnvironmentVariable(name, null, null);
    }

    /**
     * Converts <code>name</code> to uppercase. All non alphanumeric characters are
     * converted to underscores. If <code>naming</code> is <code>basename</code>
     * then the environment variable name is anything after the last '/' in the
     * parameter name, if it is <code>relative</code> then the environment variable
     * name is anything after the <code>path</code>, otherwise the full path is
     * used.
     *
     * @param name   parameter name
     * @param path   hierarchy for the parameter
     * @param naming environment variable naming: basename, relative, absolute
     */
    private String toEnvironmentVariable(String name, String path, String naming) {
        StringBuffer environmentVariable = new StringBuffer();
        int start = 0;
        if (path != null) {
            if (NAMING_RELATIVE.equals(naming)) {
                if (name.length() > path.length()) {
                    start = path.length();
                }
            } else if (NAMING_ABSOLUTE.equals(naming)) {
                start = 1;
            } else {
                start = name.lastIndexOf('/') + 1;
            }
        }
        if (name.charAt(start) == '/') {
            start++;
        }
        for (int i = start; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isLetter(c)) {
                environmentVariable.append(c);
            } else if (Character.isDigit(c)) {
                environmentVariable.append(c);
            } else {
                environmentVariable.append('_');
            }
        }
        return environmentVariable.toString();
    }
}
