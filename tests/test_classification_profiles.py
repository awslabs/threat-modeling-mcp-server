"""Tests for classification models, system context, and exported profiles."""

import pytest

import threat_modeling_mcp_server.models.models as M
import threat_modeling_mcp_server.models.data_classification_models as DC
import threat_modeling_mcp_server.models.user_models as UM
import threat_modeling_mcp_server.models.nfr_models as NF
import threat_modeling_mcp_server.models.asset_flow_models as AF
import threat_modeling_mcp_server.models.threat_actor_models as TA


class TestNFRProfile:
    """Flat quality class and level model."""

    def test_twenty_one_quality_classes(self):
        assert len(list(NF.QualityClass)) == 21

    def test_every_class_has_levels(self):
        for quality_class in NF.QualityClass:
            assert NF.CLASS_LEVELS[quality_class], f"{quality_class} has no levels"

    def test_requirement_serialization_is_flat(self):
        requirement = NF.NonFunctionalRequirement(
            quality_class="Availability", level="99.9%",
        )
        assert requirement.model_dump(mode="json") == {
            "quality_class": "Availability",
            "level": "99.9%",
            "rationale": None,
        }

    def test_level_must_belong_to_the_class(self):
        with pytest.raises(ValueError):
            NF.NonFunctionalRequirement(quality_class="Availability", level="Elastic")

    def test_profile_lookup(self):
        profile = NF.NFRProfile(requirements=[
            NF.NonFunctionalRequirement(quality_class="Scalability", level="Elastic"),
        ])
        assert profile.get_level(NF.QualityClass.SCALABILITY) == "Elastic"
        assert profile.get_level(NF.QualityClass.AVAILABILITY) is None


class TestAssetDataStates:
    """Assets support multiple physical data states."""

    def test_asset_accepts_multiple_data_states(self):
        asset = AF.Asset(
            id="A1", name="Lab results", type=AF.AssetType.DATA,
            classification="Restricted", lifecycle_state="Active",
            data_states=["At rest", "In transit"],
        )
        assert [d.value for d in asset.data_states] == ["At rest", "In transit"]

    def test_data_states_defaults_to_empty(self):
        asset = AF.Asset(id="A2", name="x", type=AF.AssetType.DATA,
                         classification="Public")
        assert asset.data_states == []

    def test_single_string_is_coerced_to_list(self):
        asset = AF.Asset(id="A3", name="x", type=AF.AssetType.DATA,
                         classification="Public", data_states="In use")
        assert asset.data_states == [DC.DataState.IN_USE]

    def test_asset_and_data_profile_coerce_scalar_state_identically(self):
        asset = AF.Asset(
            id="A4",
            name="x",
            type="Data",
            classification="Internal",
            data_states="At rest",
        )
        profile = DC.DataAssetProfile(
            id="DP001",
            structural_category="Structured Data",
            data_states="At rest",
        )

        assert [state.value for state in asset.data_states] == ["At rest"]
        assert [state.value for state in profile.data_states] == ["At rest"]


class TestUserPersona:
    """Persona entity and authentication behavior."""

    def test_persona_records_entity_type_and_authentication(self):
        persona = UM.UserPersona(
            id="U1", persona_type="System Administrator",
            entity_type="Human", authentication_method="Multi-factor",
            privilege_level="Administrative",
        )
        assert persona.entity_type is UM.EntityType.HUMAN
        assert persona.authentication_method.value == "Multi-factor"

    def test_intent_defaults_to_legitimate(self):
        persona = UM.UserPersona(id="U2", persona_type="Data Subject")
        assert persona.intent_behavior is UM.IntentBehavior.LEGITIMATE


class TestDefaultThreatActors:
    """Default library contents."""

    def test_defaults_cover_twelve_of_thirteen_types(self):
        actors = TA.ThreatActorLibrary().get_default_actors()
        assert len(actors) == 12
        types = {a.type for a in actors.values()}
        assert TA.ThreatActorType.OTHER not in types
        assert len(types) == 12

    def test_defaults_populate_actor_facets(self):
        actors = TA.ThreatActorLibrary().get_default_actors()
        for actor in actors.values():
            assert actor.relationship_to_target is not None
            assert actor.sophistication_tier is not None
            assert actor.state_nexus is not None
            assert actor.targeting_specificity is not None


class _Ctx:
    """Minimal MCP context stub."""

    async def error(self, *args, **kwargs):
        pass

    async def info(self, *args, **kwargs):
        pass


class TestClassificationProfileTools:
    """Classification profiles must be settable, collected, and exported."""

    @pytest.fixture(autouse=True)
    def reset_profiles(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp

        cp.reset_classification_profiles()
        yield
        cp.reset_classification_profiles()

    @pytest.mark.asyncio
    async def test_delete_nfr_requirement_is_case_insensitive(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp

        await cp.set_nfr_requirement_impl(_Ctx(), "Availability", "99.9%")
        result = await cp.delete_nfr_requirement_impl(_Ctx(), "availability")

        assert "removed" in result
        assert cp.nfr_profile.requirements == []

    @pytest.mark.asyncio
    async def test_delete_nfr_requirement_lists_options_for_bad_class(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp

        with pytest.raises(ValueError) as exc:
            await cp.delete_nfr_requirement_impl(_Ctx(), "Nonexistent Class")

        assert "Valid options are" in str(exc.value)

    @pytest.mark.asyncio
    async def test_software_profile_round_trip(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp

        await cp.set_software_profile_impl(
            _Ctx(), "SaaS / Multi-Tenant Application", deployment_model="PaaS",
            architecture_style="Microservices", platform_runtime="Container",
            user_domain="Healthcare", licensing_ownership="Internal custom-built",
            modern_paradigms=["Cloud-native"],
        )
        out = await cp.get_software_profile_impl(_Ctx())
        assert "SaaS / Multi-Tenant Application" in out
        assert "Microservices" in out
        assert "Cloud-native" in out

    @pytest.mark.asyncio
    async def test_data_asset_profile_round_trip(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp

        await cp.add_data_asset_profile_impl(
            _Ctx(), "Structured Data", content_types=["PHI"],
            sensitivity_tier="Restricted", compliance_regimes=["HIPAA"],
            data_states=["At rest", "In transit"], volume_tier="Medium",
            lifecycle_state="Active", business_domain="Healthcare",
        )
        out = await cp.list_data_asset_profiles_impl(_Ctx())
        assert "Structured Data" in out and "PHI" in out
        assert "At rest, In transit" in out

    @pytest.mark.asyncio
    async def test_user_persona_round_trip(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp

        await cp.add_user_persona_impl(
            _Ctx(), "Support / Operator User", privilege_level="Elevated",
            organizational_affiliation="Employee", functional_roles=["Support"],
            entity_type="Human", authentication_method="Multi-factor",
            threat_actor_overlay=["TA001"],
        )
        out = await cp.list_user_personas_impl(_Ctx())
        assert "Support / Operator User" in out
        assert "Elevated" in out and "TA001" in out

    @pytest.mark.asyncio
    async def test_nfr_requirement_round_trip_and_replacement(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp

        await cp.set_nfr_requirement_impl(_Ctx(), "Availability", "99.9%")
        await cp.set_nfr_requirement_impl(_Ctx(), "Scalability", "Elastic")
        # setting the same class again replaces rather than duplicates
        result = await cp.set_nfr_requirement_impl(_Ctx(), "Availability", "99.99%")

        assert len(cp.nfr_profile.requirements) == 2
        assert cp.nfr_profile.get_level(NF.QualityClass.AVAILABILITY) == "99.99%"
        out = await cp.list_nfr_requirements_impl(_Ctx())
        assert "**Availability**: 99.99%" in out
        assert ">" not in out
        assert result == "NFR set: Availability: 99.99%"

    @pytest.mark.asyncio
    async def test_invalid_nfr_level_is_rejected(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp

        with pytest.raises(ValueError):
            await cp.set_nfr_requirement_impl(_Ctx(), "Availability", "Elastic")

    @pytest.mark.asyncio
    async def test_profiles_reach_state_and_markdown_export(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp
        from threat_modeling_mcp_server.utils.state_collector import (
            collect_all_state, get_state_summary,
        )
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            generate_threat_model_markdown,
        )

        await cp.set_software_profile_impl(_Ctx(), "API Service", deployment_model="PaaS")
        await cp.add_data_asset_profile_impl(_Ctx(), "Secrets and Credentials",
                                             sensitivity_tier="Restricted")
        await cp.add_user_persona_impl(_Ctx(), "System Administrator")
        await cp.set_nfr_requirement_impl(_Ctx(), "Availability", "99.99%")

        state = collect_all_state()
        assert state.software_profile is not None
        assert len(state.data_asset_profiles) == 1
        assert len(state.user_personas) == 1
        assert len(state.nfr_requirements) == 1

        summary = get_state_summary()["classification_profiles"]
        assert summary["software_profile_set"] is True
        assert summary["data_asset_profiles"] == 1
        assert summary["user_personas"] == 1
        assert summary["nfr_requirements"] == 1

        md = generate_threat_model_markdown(state)
        assert "## Classification Profiles" in md
        assert "API Service" in md
        assert "Secrets and Credentials" in md
        assert "System Administrator" in md
        assert "**Availability**: 99.99%" in md


class TestNFRProfileUniqueness:
    """A profile may not hold the same class twice."""

    def test_duplicate_classes_rejected(self):
        with pytest.raises(ValueError):
            NF.NFRProfile(requirements=[
                NF.NonFunctionalRequirement(quality_class="Availability", level="99%"),
                NF.NonFunctionalRequirement(quality_class="Availability", level="99.9%"),
            ])


class TestPhaseOneCompletionIsSingleSourced:
    """One definition of phase-1 completeness."""

    def test_state_summary_matches_validation(self):
        import threat_modeling_mcp_server.tools.business_context as bctx
        from threat_modeling_mcp_server.utils.state_collector import get_state_summary

        summary = get_state_summary()["business_context"]
        complete, missing = bctx.check_business_context_completeness()

        assert summary["features_total"] == len(bctx.REQUIRED_BUSINESS_CONTEXT_FEATURES)
        # "description" is reported alongside the features but counted separately
        missing_features = [m for m in missing if m != "description"]
        assert summary["features_set"] == summary["features_total"] - len(missing_features)
        # completeness includes the description, so the two agree exactly
        assert summary["is_complete"] == complete


class TestJsonExportWiring:
    """Profiles must reach the JSON export, not just Markdown."""

    @pytest.fixture(autouse=True)
    def reset_profiles(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp

        cp.reset_classification_profiles()
        yield
        cp.reset_classification_profiles()

    @pytest.mark.asyncio
    async def test_extended_export_data_contains_profiles(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp
        from threat_modeling_mcp_server.utils.state_collector import collect_all_state
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            build_extended_export_data,
        )

        await cp.set_software_profile_impl(_Ctx(), "API Service", deployment_model="PaaS")
        await cp.add_data_asset_profile_impl(_Ctx(), "Secrets and Credentials",
                                             name="Signing keys",
                                             sensitivity_tier="Restricted")
        await cp.add_user_persona_impl(_Ctx(), "System Administrator")
        await cp.set_nfr_requirement_impl(_Ctx(), "Availability", "99.99%")

        data = build_extended_export_data(collect_all_state())

        assert data["softwareProfile"]["software_type"] == "API Service"
        assert len(data["dataAssetProfiles"]) == 1
        assert data["dataAssetProfiles"][0]["id"] == "DP001"
        assert data["dataAssetProfiles"][0]["name"] == "Signing keys"
        assert len(data["userPersonas"]) == 1
        assert data["userPersonas"][0]["id"] == "UP001"
        assert data["nonFunctionalRequirements"][0] == {
            "quality_class": "Availability",
            "level": "99.99%",
            "rationale": None,
        }
        assert "phaseProgress" in data and "businessContext" in data

    def test_business_context_dict_does_not_crash(self):
        import threat_modeling_mcp_server.tools.business_context as bctx
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            convert_business_context_to_dict,
        )

        result = convert_business_context_to_dict(bctx.business_context)
        assert "features" in result

    def test_generic_conversion_preserves_dictionary_keys(self):
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            convert_generic_objects_to_dict,
        )
        from threat_modeling_mcp_server.models.user_models import UserPersona

        objects = {"UP007": UserPersona(id="UP007", persona_type="Data Subject")}
        assert convert_generic_objects_to_dict(objects)[0]["id"] == "UP007"

    @pytest.mark.asyncio
    async def test_markdown_toc_lists_classification_profiles(self):
        from threat_modeling_mcp_server.utils.state_collector import collect_all_state
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            generate_threat_model_markdown,
        )

        md = generate_threat_model_markdown(collect_all_state())
        assert "[Classification Profiles](#classification-profiles)" in md


class TestGeographicFacets:
    """Geographic profile facets must be settable and exported."""

    @pytest.mark.asyncio
    async def test_facets_round_trip_through_tool_and_export(self):
        import threat_modeling_mcp_server.tools.business_context as bctx
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            convert_business_context_to_dict,
        )

        await bctx.clear_business_context_impl(_Ctx())
        await bctx.set_business_context_with_features_impl(
            _Ctx(), "portal",
            data_residency="National / Single-Country",
            compute_location="Regional / Multi-Country Bloc",
            user_base_location="Global / Transboundary",
            organizational_headquarters="National / Single-Country",
        )

        profile = bctx.business_context.geographic_profile
        assert profile.data_residency is M.GeographicScope.NATIONAL
        assert profile.user_base_location is M.GeographicScope.GLOBAL

        exported = convert_business_context_to_dict(bctx.business_context)
        facets = exported["features"]["geographic_profile"]
        assert facets["compute_location"] == "Regional / Multi-Country Bloc"
        assert len(facets) == 4

        summary = await bctx.get_business_context_impl(_Ctx())
        assert "Geographic Facets" in summary


class TestInvalidValueReportingIsComplete:
    """Every business context enum failure must reach the caller."""

    @pytest.mark.asyncio
    async def test_all_rejected_fields_are_reported(self):
        import threat_modeling_mcp_server.tools.business_context as bctx

        await bctx.clear_business_context_impl(_Ctx())
        result = await bctx.set_business_context_with_features_impl(
            _Ctx(), "x", industry_sector="Nope", sensitivity_tier="Regulated",
            regulatory_requirements="HIPPA", user_base_size="Enterprise",
            deployment_model="Cloud-Public", data_residency="Multinational",
        )
        assert "BUSINESS CONTEXT REJECTED" in result
        for field in ("industry_sector", "sensitivity_tier", "regulatory_requirements",
                      "user_base_size", "deployment_model", "data_residency"):
            assert field in result, f"{field} failure was not reported"
        # every message names the valid options
        assert "Valid options are:" in result


class TestOutputRendering:
    """Exports render enum values rather than enum object representations."""

    @pytest.mark.asyncio
    async def test_markdown_renders_actor_enum_values(self):
        import threat_modeling_mcp_server.tools.threat_actor_analyzer as taa
        from threat_modeling_mcp_server.utils.state_collector import collect_all_state
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            generate_threat_model_markdown,
        )

        # The actor has to be one the agent added: the report body covers only
        # reviewed records, and the pre-loaded default library is not reviewed.
        taa.initialize_threat_actors()
        await taa.add_threat_actor_impl(
            _Ctx(),
            name="Disgruntled Operator",
            type="Insider Threat",
            sophistication_tier="Tier 1 - Opportunistic / script kiddie",
            motivations=["Financial gain"],
            resources="Individual",
        )
        md = generate_threat_model_markdown(collect_all_state())
        for leak in ("ThreatActorType.", "ResourceLevel.", "Motivation.",
                     "SophisticationTier.", "StateNexus.", "CapabilityLevel."):
            assert leak not in md, f"{leak} rendered as an enum object"
        assert "- **Type**: Insider Threat" in md

    @pytest.mark.asyncio
    async def test_markdown_renders_trust_boundary_enum_values(self):
        import threat_modeling_mcp_server.tools.trust_boundary_analyzer as tba
        from threat_modeling_mcp_server.utils.state_collector import collect_all_state
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            generate_threat_model_markdown,
        )

        await tba.add_trust_zone_impl(_Ctx(), name="Payments VPC", trust_level="Medium")
        await tba.add_trust_boundary_impl(
            _Ctx(), name="Payments Boundary", type="Network",
        )
        md = generate_threat_model_markdown(collect_all_state())

        for leak in ("TrustLevel.", "BoundaryType."):
            assert leak not in md, f"{leak} rendered as an enum object"
        assert "- **Trust Level**: Medium" in md
        assert "- **Type**: Network" in md

    @pytest.mark.asyncio
    async def test_multiple_other_is_not_filtered_from_output(self):
        import threat_modeling_mcp_server.tools.business_context as bctx

        await bctx.clear_business_context_impl(_Ctx())
        await bctx.set_business_context_with_features_impl(
            _Ctx(), "x", regulatory_requirements="Multiple / other",
        )
        summary = await bctx.get_business_context_impl(_Ctx())
        assert "Multiple / other" in summary

    def test_export_summary_does_not_claim_standard_only_when_extended(
        self, tmp_path, monkeypatch
    ):
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            export_comprehensive_threat_model,
        )

        # The exporter writes into ./.threatmodel, so run in a temp working
        # directory. Never delete the repository's .threatmodel directory.
        monkeypatch.chdir(tmp_path)

        with_extended = export_comprehensive_threat_model("claim_test", True)
        assert "contains only standard schema fields" not in with_extended
        assert "extended taxonomy keys" in with_extended

        standard_only = export_comprehensive_threat_model("claim_test_std", False)
        assert "contains only standard schema fields" in standard_only


class TestMarkdownExportIsComplete:
    """The comprehensive report must include every configured profile field."""

    @pytest.mark.asyncio
    async def test_all_profile_fields_are_rendered(self):
        import threat_modeling_mcp_server.tools.business_context as bctx
        import threat_modeling_mcp_server.tools.classification_profiles as cp
        import threat_modeling_mcp_server.tools.asset_flow_analyzer as afa
        from threat_modeling_mcp_server.utils.state_collector import collect_all_state
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            generate_threat_model_markdown,
        )

        cp.reset_classification_profiles()
        await bctx.set_business_context_with_features_impl(
            _Ctx(), "portal",
            data_residency="National / Single-Country",
            organizational_headquarters="National / Single-Country",
        )
        await cp.add_data_asset_profile_impl(
            _Ctx(), "Structured Data", name="Labs", asset_id="A001",
            content_types=["PHI"], sensitivity_tier="Restricted",
            compliance_regimes=["HIPAA"], data_states=["At rest"],
            volume_tier="Big data", lifecycle_state="Active",
            business_domain="Healthcare",
        )
        await cp.add_user_persona_impl(
            _Ctx(), "Support / Operator User", name="Helpdesk",
            privilege_level="Elevated", organizational_affiliation="Employee",
            functional_roles=["Support"], entity_type="Human",
            authentication_method="Multi-factor", threat_actor_overlay=["TA001"],
        )
        await cp.set_nfr_requirement_impl(
            _Ctx(), "Availability", "99.9%", rationale="clinical use",
        )
        await afa.add_asset_impl(
            _Ctx(), "Lab results", "Data", "Restricted",
            lifecycle_state="Active", data_states=["At rest", "In transit"],
        )

        md = generate_threat_model_markdown(collect_all_state())

        for expected in ("Big data", "Healthcare", "HIPAA",          # data profile
                         "Support", "Multi-factor", "TA001",          # persona
                         "clinical use",                              # NFR rationale
                         "At rest, In transit",                       # asset data states
                         "Data Residency", "Organizational HQ"):      # geographic facets
            assert expected in md, f"markdown export dropped {expected!r}"

        for leak in ("AssetType.", "SensitivityTier.", "DataState.",
                     "DataLifecycleState."):
            assert leak not in md, f"{leak} rendered as an enum object"

        cp.reset_classification_profiles()


class TestGeographicFacetsAreRequired:
    """A complete geographic classification assigns a level to every facet."""

    @pytest.mark.asyncio
    async def test_phase_one_incomplete_without_all_facets(self):
        import threat_modeling_mcp_server.tools.business_context as bctx

        base = dict(
            industry_sector="Healthcare", sensitivity_tier="Restricted",
            user_base_size="Medium", user_base_metric="Monthly Active Users",
            geographic_scope="National / Single-Country",
            regulatory_requirements="HIPAA", system_criticality="High",
            financial_impact="Moderate", revenue_band="Mid-market",
            authentication_requirement="MFA", deployment_model="PaaS",
        )

        await bctx.clear_business_context_impl(_Ctx())
        await bctx.set_business_context_with_features_impl(_Ctx(), "portal", **base)
        complete, missing = bctx.check_business_context_completeness()
        assert not complete and "geographic_profile" in missing

        # three of four facets is still incomplete
        await bctx.set_business_context_with_features_impl(
            _Ctx(), "portal", **base,
            data_residency="National / Single-Country",
            compute_location="National / Single-Country",
            user_base_location="Global / Transboundary",
        )
        complete, missing = bctx.check_business_context_completeness()
        assert not complete and "geographic_profile" in missing

        await bctx.set_business_context_with_features_impl(
            _Ctx(), "portal", **base,
            data_residency="National / Single-Country",
            compute_location="National / Single-Country",
            user_base_location="Global / Transboundary",
            organizational_headquarters="National / Single-Country",
        )
        complete, missing = bctx.check_business_context_completeness()
        assert complete, f"still missing: {missing}"


class TestSummaryAgreesWithValidation:
    """The state summary must not report complete when validation does not."""

    @pytest.mark.asyncio
    async def test_partial_geographic_profile_is_not_complete(self):
        import threat_modeling_mcp_server.tools.business_context as bctx
        from threat_modeling_mcp_server.utils.state_collector import get_state_summary

        base = dict(
            industry_sector="Healthcare", sensitivity_tier="Restricted",
            user_base_size="Medium", user_base_metric="Monthly Active Users",
            geographic_scope="National / Single-Country",
            regulatory_requirements="HIPAA", system_criticality="High",
            financial_impact="Moderate", revenue_band="Mid-market",
            authentication_requirement="MFA", deployment_model="PaaS",
        )

        await bctx.clear_business_context_impl(_Ctx())
        await bctx.set_business_context_with_features_impl(
            _Ctx(), "portal", **base,
            data_residency="National / Single-Country",  # only one of four
        )

        complete, missing = bctx.check_business_context_completeness()
        summary = get_state_summary()["business_context"]

        assert not complete
        assert summary["is_complete"] is False
        assert summary["features_set"] < summary["features_total"]
        assert summary["missing_features"] == missing


class TestDescriptionsAreExported:
    """Descriptions and scope flags must survive into the outputs."""

    @pytest.mark.asyncio
    async def test_profile_descriptions_and_scope_reach_markdown(self):
        import threat_modeling_mcp_server.tools.classification_profiles as cp
        from threat_modeling_mcp_server.utils.state_collector import collect_all_state
        from threat_modeling_mcp_server.utils.comprehensive_exporter import (
            generate_threat_model_markdown,
        )

        cp.reset_classification_profiles()
        try:
            await cp.set_software_profile_impl(
                _Ctx(), "API Service", description="payments edge service",
            )
            await cp.add_data_asset_profile_impl(
                _Ctx(), "Structured Data", description="cardholder records",
            )
            await cp.add_user_persona_impl(
                _Ctx(), "Data Subject", description="cardholder",
            )
            await cp.update_user_persona_impl(_Ctx(), "UP001", is_relevant=False)

            md = generate_threat_model_markdown(collect_all_state())
            assert "payments edge service" in md
            assert "cardholder records" in md
            assert "cardholder" in md
            assert "| No |" in md  # persona marked out of scope

            listing = await cp.list_user_personas_impl(_Ctx())
            assert "In Scope" in listing and "cardholder" in listing
        finally:
            cp.reset_classification_profiles()
