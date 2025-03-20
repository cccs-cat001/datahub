package io.datahubproject.iceberg.catalog.credentials;

import static com.linkedin.metadata.authorization.PoliciesConfig.*;
import static org.apache.iceberg.azure.AzureProperties.ADLS_SAS_TOKEN_PREFIX;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.common.sas.AccountSasPermission;
import com.azure.storage.common.sas.AccountSasResourceType;
import com.azure.storage.common.sas.AccountSasService;
import com.azure.storage.common.sas.AccountSasSignatureValues;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.iceberg.exceptions.BadRequestException;

public class ABFSCredentialProvider implements CredentialProvider {
  private static final int DEFAULT_CREDS_DURATION_SECS = 60 * 60;

  @Override
  public Map<String, String> getCredentials(
      CredentialsCacheKey key, StorageProviderCredentials storageProviderCredentials) {
    int expiration =
        storageProviderCredentials.tempCredentialExpirationSeconds == null
            ? DEFAULT_CREDS_DURATION_SECS
            : storageProviderCredentials.tempCredentialExpirationSeconds;
    BlobServiceClient client = client(storageProviderCredentials);
    String sas = client.generateAccountSas(signatureValues(key, expiration));
    return key.locations.stream()
        .collect(Collectors.toMap(location -> ADLS_SAS_TOKEN_PREFIX + location, location -> sas));
  }

  private BlobServiceClient client(StorageProviderCredentials storageProviderCredentials) {
    ClientSecretCredential creds =
        new ClientSecretCredentialBuilder()
            .clientId(storageProviderCredentials.clientId)
            .clientSecret(storageProviderCredentials.clientSecret)
            .build();
    return new BlobServiceClientBuilder().credential(creds).buildClient();
  }

  private AccountSasSignatureValues signatureValues(CredentialsCacheKey key, int expiration) {
    if (key.locations == null || key.locations.isEmpty()) {
      throw new BadRequestException("Unspecified locations for credential vending.");
    }
    if (!Set.of(DATA_READ_WRITE_PRIVILEGE, DATA_READ_ONLY_PRIVILEGE).contains(key.privilege)) {
      throw new IllegalStateException("Unsupported credential vending privilege " + key.privilege);
    }
    OffsetDateTime expiry = OffsetDateTime.now().withSecond(expiration);
    /** w - write r - read c - create d - delete l - list ref: {@link AccountSasPermission} */
    AccountSasPermission permissions = AccountSasPermission.parse("wrcdl");
    /** b - blob ref - {@link AccountSasService} */
    AccountSasService service = AccountSasService.parse("b");
    /** c - container ref - {@link AccountSasResourceType} */
    AccountSasResourceType resourceType = AccountSasResourceType.parse("c");
    return new AccountSasSignatureValues(expiry, permissions, service, resourceType);
  }
}
