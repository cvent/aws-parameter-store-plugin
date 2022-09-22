/**
  * MIT License
  *
  * Copyright (c) 2018 Rik Turnbull
  *
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  *
  * The above copyright notice and this permission notice shall be included in all
  * copies or substantial portions of the Software.
  *
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  * SOFTWARE.
  */
package hudson.plugins.awsparameterstore;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.logging.Logger;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.RegionUtils;
import com.amazonaws.services.simplesystemsmanagement.model.Parameter;
import com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsHelper;

import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.console.ConsoleLogFilter;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildWrapperDescriptor;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildWrapper;

/**
 * A Jenkins {@link hudson.tasks.BuildWrapper} for AWS Parameter Store.
 *
 * @author Rik Turnbull
 *
 */
public class AwsParameterStoreBuildWrapper extends SimpleBuildWrapper {

  private static final Logger LOGGER = Logger.getLogger(AwsParameterStoreBuildWrapper.class.getName());
  private static final String SECURE_STRING_TYPE = "SecureString";

  private static final String DEFAULT_OPTION = "BeginsWith";

  private String credentialsId;
  private String regionName;
  private String path;
  private Boolean recursive;
  private String naming;
  private String namePrefixes;
  private Boolean hideSecureStrings;
  private Set<String> secrets;
  private String option;

  /**
   * Creates a new {@link AwsParameterStoreBuildWrapper}.
   */
  @DataBoundConstructor
  public AwsParameterStoreBuildWrapper() {
    this(null, null, null, false, null, null, false, null);
  }

  /**
   * Creates a new {@link AwsParameterStoreBuildWrapper}.
   *
   * @param credentialsId     aws credentials id
   * @param regionName        aws region name
   * @param path              hierarchy for the parameter
   * @param recursive         fetch all parameters within a hierarchy
   * @param naming            environment variable naming: basename, absolute,
   *                          relative
   * @param namePrefixes      filter parameters by Name with beginsWith filter
   * @param hideSecureStrings remove secure string values from the console
   * @param option            option for filter operation
   */
  @Deprecated
  public AwsParameterStoreBuildWrapper(String credentialsId, String regionName, String path, Boolean recursive,
      String naming, String namePrefixes, Boolean hideSecureStrings, String option) {
    this.credentialsId = credentialsId;
    this.regionName = regionName;
    this.path = path;
    this.recursive = recursive;
    this.naming = naming;
    this.namePrefixes = namePrefixes;
    this.hideSecureStrings = hideSecureStrings;
    this.option = option != null ? option : DEFAULT_OPTION;
  }

  synchronized private Set<String> getSecrets() {
    if (null == secrets) {
      secrets = new CopyOnWriteArraySet<>();
    }
    return secrets;
  }

  /**
   * Gets AWS credentials identifier.
   *
   * @return AWS credentials identifier
   */
  public String getCredentialsId() {
    return credentialsId;
  }

  /**
   * Sets the AWS credentials identifier.
   *
   * @param credentialsId aws credentials id
   */
  @DataBoundSetter
  public void setCredentialsId(String credentialsId) {
    this.credentialsId = StringUtils.stripToNull(credentialsId);
  }

  /**
   * Gets AWS region name.
   *
   * @return aws region name
   */
  public String getRegionName() {
    return regionName;
  }

  /**
   * Sets the AWS region name.
   *
   * @param regionName aws region name
   */
  @DataBoundSetter
  public void setRegionName(String regionName) {
    this.regionName = regionName;
  }

  /**
   * Gets path.
   *
   * @return path
   */
  public String getPath() {
    return path;
  }

  /**
   * Sets the AWS Parameter Store hierarchy.
   *
   * @param path aws parameter store hierarchy
   */
  @DataBoundSetter
  public void setPath(String path) {
    this.path = StringUtils.stripToNull(path);
  }

  /**
   * Gets recursive flag.
   *
   * @return recursive
   */
  public Boolean getRecursive() {
    return recursive;
  }

  /**
   * Sets the recursive flag.
   *
   * @param recursive recursive flag
   */
  @DataBoundSetter
  public void setRecursive(Boolean recursive) {
    this.recursive = recursive;
  }

  /**
   * Gets naming: basename, absolute, relative.
   *
   * @return naming.
   */
  public String getNaming() {
    return naming;
  }

  /**
   * Sets the naming type: basename, absolute, relative.
   *
   * @param naming the naming type
   */
  @DataBoundSetter
  public void setNaming(String naming) {
    this.naming = naming;
  }

  /**
   * Gets namePrefixes (comma separated)
   *
   * @return namePrefixes.
   */
  public String getNamePrefixes() {
    return namePrefixes;
  }

  /**
   * Sets the name prefixes filter.
   *
   * @param namePrefixes name prefixes filter
   */
  @DataBoundSetter
  public void setNamePrefixes(String namePrefixes) {
    this.namePrefixes = StringUtils.stripToNull(namePrefixes);
  }

  /**
   * Gets hideSecureStrings flag
   *
   * @return the hideSecureStrings
   */
  public Boolean getHideSecureStrings() {
    return hideSecureStrings;
  }

  /**
   * Sets the hideSecureStrings flag
   *
   * @param hideSecureStrings the hideSecureStrings to set
   */
  @DataBoundSetter
  public void setHideSecureStrings(Boolean hideSecureStrings) {
    this.hideSecureStrings = hideSecureStrings;
  }

  /**
   * Gets option
   * @return option
   */
  public String getOption() {
    return option;
  }

  /**
   * Sets the option parameter
   */
  @DataBoundSetter
  public void setOption(String option) {
    this.option = option;
  }

  synchronized private void addSecrets(List<Parameter> params) {
    List<String> secrets = new LinkedList<>();
    for (Parameter param : params) {
      if (StringUtils.equals(SECURE_STRING_TYPE, param.getType())) {
        secrets.add(param.getValue());
      }
    }
    getSecrets().addAll(secrets);
  }

  @Override
  public void setUp(Context context, Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener,
      EnvVars initialEnvironment) throws IOException, InterruptedException {
    AwsParameterStoreService awsParameterStoreService = new AwsParameterStoreService(credentialsId, regionName);
    LOGGER.fine("Fetching Parameters");
    List<Parameter> params = awsParameterStoreService.fetchParameters(path, recursive, namePrefixes, option);
    if (hideSecureStrings) {
      addSecrets(params);
    }
    LOGGER.fine(String.format("Fetched Parameters. Retrieved %d", params.size()));
    awsParameterStoreService.buildEnvVars(context, path, naming, params);
  }

  @Override
  public ConsoleLogFilter createLoggerDecorator(Run<?, ?> build) {
    return new FilterImpl(getSecrets());
  }

  private static final class FilterImpl extends ConsoleLogFilter implements Serializable {

    private static final long serialVersionUID = 1L;
    private final Set<String> secrets;

    FilterImpl(Set<String> secrets) {
      this.secrets = secrets;
    }

    @Override
    public OutputStream decorateLogger(AbstractBuild _ignore, OutputStream logger)
        throws IOException, InterruptedException {
      return new AwsParameterStoreOutputStream(logger, secrets);
    }
  }

  /**
   * A Jenkins <code>BuildWrapperDescriptor</code> for the
   * {@link AwsParameterStoreBuildWrapper}.
   *
   * @author Rik Turnbull
   *
   */
  @Extension
  @Symbol("withAWSParameterStore")
  public static final class DescriptorImpl extends BuildWrapperDescriptor {
    @Override
    public String getDisplayName() {
      return Messages.displayName();
    }

    /**
     * Returns a list of AWS credentials identifiers.
     *
     * @return {@link ListBoxModel} populated with AWS credential identifiers
     */
    public ListBoxModel doFillCredentialsIdItems() {
      return AWSCredentialsHelper.doFillCredentialsIdItems(Jenkins.getActiveInstance());
    }

    /**
     * Returns a list of AWS region names.
     *
     * @return {@link ListBoxModel} populated with AWS region names
     */
    public ListBoxModel doFillRegionNameItems() {
      final ListBoxModel options = new ListBoxModel();
      final List<String> regionNames = new ArrayList<String>();
      final List<Region> regions = RegionUtils.getRegions();
      for (Region region : regions) {
        regionNames.add(region.getName());
      }
      Collections.sort(regionNames);
      options.add("- select -", null);
      for (String regionName : regionNames) {
        options.add(regionName);
      }
      return options;
    }

    /**
     * Returns a list of naming options: basename, absolute, relative.
     *
     * @return {@link ListBoxModel} populated with AWS region names
     */
    public ListBoxModel doFillNamingItems() {
      final ListBoxModel options = new ListBoxModel();
      options.add("- select -", null);
      options.add(AwsParameterStoreService.NAMING_BASENAME);
      options.add(AwsParameterStoreService.NAMING_RELATIVE);
      options.add(AwsParameterStoreService.NAMING_ABSOLUTE);
      return options;
    }

    @Override
    public boolean isApplicable(AbstractProject item) {
      return true;
    }
  }
}
