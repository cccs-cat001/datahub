package com.linkedin.gms.factory.common;

import com.linkedin.gms.factory.config.ConfigurationProvider;
import com.linkedin.gms.factory.search.BaseElasticSearchComponentsFactory;
import com.linkedin.metadata.graph.GraphService;
import com.linkedin.metadata.graph.elastic.ESGraphQueryDAO;
import com.linkedin.metadata.graph.elastic.ESGraphWriteDAO;
import com.linkedin.metadata.graph.elastic.ElasticSearchGraphService;
import com.linkedin.metadata.models.registry.EntityRegistry;
import com.linkedin.metadata.models.registry.LineageRegistry;
import com.linkedin.metadata.utils.metrics.MetricUtils;
import javax.annotation.Nonnull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@ConditionalOnProperty(
    name = "graphService.type",
    havingValue = "elasticsearch",
    matchIfMissing = true)
@Import({BaseElasticSearchComponentsFactory.class})
public class ElasticSearchGraphServiceFactory {
  @Autowired
  @Qualifier("baseElasticSearchComponents")
  private BaseElasticSearchComponentsFactory.BaseElasticSearchComponents components;

  @Bean(name = "graphService")
  @Nonnull
  protected GraphService getInstance(
      final ConfigurationProvider configurationProvider,
      final EntityRegistry entityRegistry,
      @Value("${elasticsearch.idHashAlgo}") final String idHashAlgo,
      MetricUtils metricUtils) {
    LineageRegistry lineageRegistry = new LineageRegistry(entityRegistry);
    return new ElasticSearchGraphService(
        lineageRegistry,
        components.getBulkProcessor(),
        components.getIndexConvention(),
        new ESGraphWriteDAO(
            components.getIndexConvention(),
            components.getBulkProcessor(),
            components.getConfig().getBulkProcessor().getNumRetries(),
            configurationProvider.getElasticSearch().getSearch().getGraph()),
        new ESGraphQueryDAO(
            components.getSearchClient(),
            lineageRegistry,
            components.getIndexConvention(),
            configurationProvider.getGraphService(),
            configurationProvider.getElasticSearch(),
            metricUtils),
        components.getIndexBuilder(),
        idHashAlgo);
  }
}
