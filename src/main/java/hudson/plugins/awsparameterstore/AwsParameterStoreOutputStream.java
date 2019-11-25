package hudson.plugins.awsparameterstore;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Set;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

import hudson.console.LineTransformationOutputStream;

public class AwsParameterStoreOutputStream extends LineTransformationOutputStream {
    private static final Logger LOGGER = Logger.getLogger(AwsParameterStoreBuildWrapper.class.getName());

    private static final String MASKED_PASSWORD = "********";

    private final OutputStream logger;
    private Pattern secureStringsAsPattern;
    private final Set<String> secureStrings;
    private int lastCount;

    public AwsParameterStoreOutputStream(OutputStream logger, Set<String> secureStrings) {
        this.logger = logger;
        this.secureStrings = secureStrings;
        this.lastCount = 0;
    }

    private Pattern getSecureStringsAsPattern(OutputStream logger) {
        if (secureStrings.size() != lastCount) {
            LOGGER.info(String.format("Building secure pattern. %d -> %d", lastCount, secureStrings.size()));
            int numSecureStrings = 0;
            StringBuilder regex = new StringBuilder().append('(');

            if (secureStrings.size() > 0) {
                for (String secureString : secureStrings) {
                    if (StringUtils.isNotEmpty(secureString)) {
                        regex.append(Pattern.quote(secureString));
                        regex.append('|');
                        try {
                            String encodedSecureString = URLEncoder.encode(secureString, "UTF-8");
                            if (!encodedSecureString.equals(secureString)) {
                                regex.append(Pattern.quote(encodedSecureString));
                                regex.append('|');
                            }
                        } catch (UnsupportedEncodingException e) {

                        }
                    }
                    numSecureStrings++;
                }
                regex.deleteCharAt(regex.length() - 1);
                regex.append(')');
                secureStringsAsPattern = Pattern.compile(regex.toString());
                lastCount = numSecureStrings;
                try {
                    logger.write(String.format("----- Now Redacting %d Secrets -----%n", secureStrings.size())
                            .getBytes());
                } catch (IOException e) {
                }
            } else {
                secureStringsAsPattern = null;
            }
        }
        return secureStringsAsPattern;
    }

    @Override
    protected void eol(byte[] bytes, int len) throws IOException {
        String line = new String(bytes, 0, len);
        Pattern secureStringsAsPattern = getSecureStringsAsPattern(logger);
        if (secureStringsAsPattern != null) {
            line = secureStringsAsPattern.matcher(line).replaceAll(MASKED_PASSWORD);
        }
        logger.write(line.getBytes());
    }

    /**
     * {@inheritDoc}
     *
     * @throws IOException
     */
    @Override
    public void close() throws IOException {
        super.close();
        logger.close();
    }

    /**
     * {@inheritDoc}
     *
     * @throws IOException
     */
    @Override
    public void flush() throws IOException {
        super.flush();
        logger.flush();
    }
}
