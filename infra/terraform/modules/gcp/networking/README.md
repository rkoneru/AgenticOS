# gcp/networking

Custom-mode VPC with one regional subnet carrying GKE pod/service secondary
ranges, plus Cloud Router + Cloud NAT for private-node egress. `region` and
all CIDRs are plain variables with documented defaults -- nothing is looked
up via a `google_compute_zones`/`google_compute_regions` data source.
