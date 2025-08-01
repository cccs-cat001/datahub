package com.linkedin.datahub.graphql.types.dataflow;

import static com.linkedin.datahub.graphql.Constants.*;
import static com.linkedin.metadata.Constants.*;

import com.datahub.authorization.ConjunctivePrivilegeGroup;
import com.datahub.authorization.DisjunctivePrivilegeGroup;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.linkedin.common.urn.CorpuserUrn;
import com.linkedin.common.urn.DataFlowUrn;
import com.linkedin.common.urn.Urn;
import com.linkedin.common.urn.UrnUtils;
import com.linkedin.data.template.StringArray;
import com.linkedin.datahub.graphql.QueryContext;
import com.linkedin.datahub.graphql.authorization.AuthorizationUtils;
import com.linkedin.datahub.graphql.exception.AuthorizationException;
import com.linkedin.datahub.graphql.generated.AutoCompleteResults;
import com.linkedin.datahub.graphql.generated.BrowsePath;
import com.linkedin.datahub.graphql.generated.BrowseResults;
import com.linkedin.datahub.graphql.generated.DataFlow;
import com.linkedin.datahub.graphql.generated.DataFlowUpdateInput;
import com.linkedin.datahub.graphql.generated.Entity;
import com.linkedin.datahub.graphql.generated.EntityType;
import com.linkedin.datahub.graphql.generated.FacetFilterInput;
import com.linkedin.datahub.graphql.generated.SearchResults;
import com.linkedin.datahub.graphql.resolvers.ResolverUtils;
import com.linkedin.datahub.graphql.types.BrowsableEntityType;
import com.linkedin.datahub.graphql.types.MutableType;
import com.linkedin.datahub.graphql.types.SearchableEntityType;
import com.linkedin.datahub.graphql.types.dataflow.mappers.DataFlowMapper;
import com.linkedin.datahub.graphql.types.dataflow.mappers.DataFlowUpdateInputMapper;
import com.linkedin.datahub.graphql.types.mappers.AutoCompleteResultsMapper;
import com.linkedin.datahub.graphql.types.mappers.BrowsePathsMapper;
import com.linkedin.datahub.graphql.types.mappers.BrowseResultMapper;
import com.linkedin.datahub.graphql.types.mappers.UrnSearchResultsMapper;
import com.linkedin.entity.EntityResponse;
import com.linkedin.entity.client.EntityClient;
import com.linkedin.metadata.Constants;
import com.linkedin.metadata.authorization.PoliciesConfig;
import com.linkedin.metadata.browse.BrowseResult;
import com.linkedin.metadata.query.AutoCompleteResult;
import com.linkedin.metadata.query.filter.Filter;
import com.linkedin.metadata.search.SearchResult;
import com.linkedin.mxe.MetadataChangeProposal;
import com.linkedin.r2.RemoteInvocationException;
import graphql.execution.DataFetcherResult;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DataFlowType
    implements SearchableEntityType<DataFlow, String>,
        BrowsableEntityType<DataFlow, String>,
        MutableType<DataFlowUpdateInput, DataFlow> {

  private static final Set<String> ASPECTS_TO_RESOLVE =
      ImmutableSet.of(
          DATA_FLOW_KEY_ASPECT_NAME,
          DATA_FLOW_INFO_ASPECT_NAME,
          EDITABLE_DATA_FLOW_PROPERTIES_ASPECT_NAME,
          OWNERSHIP_ASPECT_NAME,
          INSTITUTIONAL_MEMORY_ASPECT_NAME,
          GLOBAL_TAGS_ASPECT_NAME,
          GLOSSARY_TERMS_ASPECT_NAME,
          STATUS_ASPECT_NAME,
          DOMAINS_ASPECT_NAME,
          DEPRECATION_ASPECT_NAME,
          DATA_PLATFORM_INSTANCE_ASPECT_NAME,
          CONTAINER_ASPECT_NAME,
          DATA_PRODUCTS_ASPECT_NAME,
          BROWSE_PATHS_V2_ASPECT_NAME,
          STRUCTURED_PROPERTIES_ASPECT_NAME,
          SUB_TYPES_ASPECT_NAME,
          FORMS_ASPECT_NAME,
          APPLICATION_MEMBERSHIP_ASPECT_NAME);
  private static final Set<String> FACET_FIELDS = ImmutableSet.of("orchestrator", "cluster");
  private final EntityClient _entityClient;

  public DataFlowType(final EntityClient entityClient) {
    _entityClient = entityClient;
  }

  @Override
  public EntityType type() {
    return EntityType.DATA_FLOW;
  }

  @Override
  public Function<Entity, String> getKeyProvider() {
    return Entity::getUrn;
  }

  @Override
  public Class<DataFlow> objectClass() {
    return DataFlow.class;
  }

  @Override
  public Class<DataFlowUpdateInput> inputClass() {
    return DataFlowUpdateInput.class;
  }

  @Override
  public List<DataFetcherResult<DataFlow>> batchLoad(
      final List<String> urnStrs, @Nonnull final QueryContext context) throws Exception {
    final List<Urn> urns = urnStrs.stream().map(UrnUtils::getUrn).collect(Collectors.toList());
    try {
      final Map<Urn, EntityResponse> dataFlowMap =
          _entityClient.batchGetV2(
              context.getOperationContext(),
              Constants.DATA_FLOW_ENTITY_NAME,
              new HashSet<>(urns),
              ASPECTS_TO_RESOLVE);

      final List<EntityResponse> gmsResults = new ArrayList<>(urnStrs.size());
      for (Urn urn : urns) {
        gmsResults.add(dataFlowMap.getOrDefault(urn, null));
      }
      return gmsResults.stream()
          .map(
              gmsDataFlow ->
                  gmsDataFlow == null
                      ? null
                      : DataFetcherResult.<DataFlow>newResult()
                          .data(DataFlowMapper.map(context, gmsDataFlow))
                          .build())
          .collect(Collectors.toList());
    } catch (Exception e) {
      throw new RuntimeException("Failed to batch load Data Flows", e);
    }
  }

  @Override
  public SearchResults search(
      @Nonnull String query,
      @Nullable List<FacetFilterInput> filters,
      int start,
      @Nullable Integer count,
      @Nonnull final QueryContext context)
      throws Exception {
    final Map<String, String> facetFilters = ResolverUtils.buildFacetFilters(filters, FACET_FIELDS);
    final SearchResult searchResult =
        _entityClient.search(
            context.getOperationContext().withSearchFlags(flags -> flags.setFulltext(true)),
            "dataFlow",
            query,
            facetFilters,
            start,
            count);
    return UrnSearchResultsMapper.map(context, searchResult);
  }

  @Override
  public AutoCompleteResults autoComplete(
      @Nonnull String query,
      @Nullable String field,
      @Nullable Filter filters,
      @Nullable Integer limit,
      @Nonnull final QueryContext context)
      throws Exception {
    final AutoCompleteResult result =
        _entityClient.autoComplete(
            context.getOperationContext(), "dataFlow", query, filters, limit);
    return AutoCompleteResultsMapper.map(context, result);
  }

  @Override
  public BrowseResults browse(
      @Nonnull List<String> path,
      @Nullable List<FacetFilterInput> filters,
      int start,
      @Nullable Integer count,
      @Nonnull QueryContext context)
      throws Exception {
    final Map<String, String> facetFilters = ResolverUtils.buildFacetFilters(filters, FACET_FIELDS);
    final String pathStr =
        path.size() > 0 ? BROWSE_PATH_DELIMITER + String.join(BROWSE_PATH_DELIMITER, path) : "";
    final BrowseResult result =
        _entityClient.browse(
            context.getOperationContext().withSearchFlags(flags -> flags.setFulltext(false)),
            "dataFlow",
            pathStr,
            facetFilters,
            start,
            count);
    return BrowseResultMapper.map(context, result);
  }

  @Override
  public List<BrowsePath> browsePaths(@Nonnull String urn, @Nonnull QueryContext context)
      throws Exception {
    final StringArray result =
        _entityClient.getBrowsePaths(
            context.getOperationContext(), DataFlowUrn.createFromString(urn));
    return BrowsePathsMapper.map(context, result);
  }

  @Override
  public DataFlow update(
      @Nonnull String urn, @Nonnull DataFlowUpdateInput input, @Nonnull QueryContext context)
      throws Exception {

    if (isAuthorized(urn, input, context)) {
      final CorpuserUrn actor = CorpuserUrn.createFromString(context.getActorUrn());
      final Collection<MetadataChangeProposal> proposals =
          DataFlowUpdateInputMapper.map(context, input, actor);
      proposals.forEach(proposal -> proposal.setEntityUrn(UrnUtils.getUrn(urn)));

      try {
        _entityClient.batchIngestProposals(context.getOperationContext(), proposals, false);
      } catch (RemoteInvocationException e) {
        throw new RuntimeException(String.format("Failed to write entity with urn %s", urn), e);
      }

      return load(urn, context).getData();
    }
    throw new AuthorizationException(
        "Unauthorized to perform this action. Please contact your DataHub administrator.");
  }

  private boolean isAuthorized(
      @Nonnull String urn, @Nonnull DataFlowUpdateInput update, @Nonnull QueryContext context) {
    // Decide whether the current principal should be allowed to update the Dataset.
    final DisjunctivePrivilegeGroup orPrivilegeGroups = getAuthorizedPrivileges(update);
    return AuthorizationUtils.isAuthorized(
        context, PoliciesConfig.DATA_FLOW_PRIVILEGES.getResourceType(), urn, orPrivilegeGroups);
  }

  private DisjunctivePrivilegeGroup getAuthorizedPrivileges(final DataFlowUpdateInput updateInput) {

    final ConjunctivePrivilegeGroup allPrivilegesGroup =
        new ConjunctivePrivilegeGroup(
            ImmutableList.of(PoliciesConfig.EDIT_ENTITY_PRIVILEGE.getType()));

    List<String> specificPrivileges = new ArrayList<>();
    if (updateInput.getOwnership() != null) {
      specificPrivileges.add(PoliciesConfig.EDIT_ENTITY_OWNERS_PRIVILEGE.getType());
    }
    if (updateInput.getEditableProperties() != null) {
      specificPrivileges.add(PoliciesConfig.EDIT_ENTITY_DOCS_PRIVILEGE.getType());
    }
    if (updateInput.getGlobalTags() != null) {
      specificPrivileges.add(PoliciesConfig.EDIT_ENTITY_TAGS_PRIVILEGE.getType());
    }
    final ConjunctivePrivilegeGroup specificPrivilegeGroup =
        new ConjunctivePrivilegeGroup(specificPrivileges);

    // If you either have all entity privileges, or have the specific privileges required, you are
    // authorized.
    return new DisjunctivePrivilegeGroup(
        ImmutableList.of(allPrivilegesGroup, specificPrivilegeGroup));
  }
}
