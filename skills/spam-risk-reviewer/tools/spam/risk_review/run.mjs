import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOOL_VERSION = "0.1.0";

function readInputs() {
  const raw = process.env.RUNX_INPUTS_PATH
    ? fs.readFileSync(process.env.RUNX_INPUTS_PATH, "utf8")
    : (process.env.RUNX_INPUTS_JSON || "{}");
  return JSON.parse(raw);
}

function packageRoot() {
  return path.resolve(__dirname, "../../..");
}

function resolveInsidePackage(relativePath, label) {
  const root = packageRoot();
  const resolved = path.resolve(root, String(relativePath || ""));
  if (!resolved.startsWith(root + path.sep) && resolved !== root) {
    throw new Error(`${label} escapes the skill package`);
  }
  return resolved;
}

function sha256Bytes(bytes) {
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function sha256Text(text) {
  return sha256Bytes(Buffer.from(text, "utf8"));
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function parseInlineJson(value, label) {
  if (typeof value === "string") {
    return JSON.parse(value);
  }
  if (value && typeof value === "object") {
    return value;
  }
  throw new Error(`${label} must be JSON text or an object`);
}

function readJsonInput(inputs, pathField, jsonField, label) {
  if (inputs[jsonField] !== undefined && inputs[jsonField] !== null && inputs[jsonField] !== "") {
    const parsed = parseInlineJson(inputs[jsonField], jsonField);
    const text = canonicalJson(parsed);
    return {
      value: parsed,
      bytes: Buffer.from(text, "utf8"),
      locator: `inline:${jsonField}`,
    };
  }
  if (inputs[pathField] !== undefined && inputs[pathField] !== null && inputs[pathField] !== "") {
    const inputPath = resolveInsidePackage(inputs[pathField], pathField);
    const bytes = fs.readFileSync(inputPath);
    return {
      value: JSON.parse(bytes.toString("utf8")),
      bytes,
      locator: String(inputs[pathField]),
    };
  }
  throw new Error(`${label} requires ${pathField} or ${jsonField}`);
}

function bool(value) {
  return value === true;
}

function textOf(campaign) {
  return [
    campaign.message?.subject,
    campaign.message?.body,
    ...(campaign.message?.claims || []),
  ].filter(Boolean).join(" ").toLowerCase();
}

function makeSignal(id, severity, scoreDelta, evidence, fix) {
  return { id, severity, score_delta: scoreDelta, evidence, fix };
}

function analyze(campaign) {
  const signals = [];
  const copy = textOf(campaign);
  const recipient = campaign.recipient || {};
  const controls = campaign.controls || {};
  const sender = campaign.sender || {};
  const plan = campaign.campaign || {};

  if (recipient.consent === "none") {
    signals.push(makeSignal("no_consent_basis", "critical", 26, "Recipient consent is none.", "Use only opt-in, transactional, or otherwise documented lawful contacts."));
  } else if (recipient.consent === "unknown") {
    signals.push(makeSignal("unknown_consent_basis", "major", 18, "Recipient consent is unknown.", "Prove the consent source before sending."));
  } else if (recipient.consent === "opt_in") {
    signals.push(makeSignal("documented_opt_in", "positive", -12, "Recipient consent is opt-in.", "Keep the opt-in source attached to the campaign record."));
  }

  if (/scraped|rented|purchased|public_directory/.test(String(recipient.source || ""))) {
    signals.push(makeSignal("unsafe_list_source", "critical", 20, `Recipient source is ${recipient.source}.`, "Remove scraped/rented/purchased recipients."));
  } else if (/first_party|account|transactional/.test(String(recipient.source || ""))) {
    signals.push(makeSignal("first_party_source", "positive", -8, `Recipient source is ${recipient.source}.`, "Retain source proof."));
  } else if (/legacy|import/.test(String(recipient.source || ""))) {
    signals.push(makeSignal("legacy_import_source", "major", 12, `Recipient source is ${recipient.source}.`, "Reconfirm consent for legacy imports."));
  }

  if (bool(plan.commercial) && !bool(controls.unsubscribe_link)) {
    signals.push(makeSignal("missing_unsubscribe", "critical", 18, "Commercial campaign has no unsubscribe link.", "Add a working unsubscribe link before sending."));
  }

  if (bool(plan.commercial) && !bool(controls.physical_address)) {
    signals.push(makeSignal("missing_sender_address", "major", 8, "Commercial campaign has no physical sender address.", "Add compliant sender address details."));
  }

  if (!bool(controls.suppression_list)) {
    signals.push(makeSignal("missing_suppression_list", "major", 8, "Suppression list control is disabled.", "Check suppression lists and honor prior opt-outs."));
  }

  if (!bool(controls.rate_limit) && Number(plan.volume_per_day || 0) > 500) {
    signals.push(makeSignal("unsafe_volume_without_rate_limit", "major", 10, `Volume is ${plan.volume_per_day} per day without rate limiting.`, "Add rate limits and ramp gradually."));
  } else if (bool(controls.rate_limit)) {
    signals.push(makeSignal("rate_limited", "positive", -4, "Rate limiting is enabled.", "Keep volume caps in the sending plan."));
  }

  if (Number(plan.volume_per_day || 0) >= 2000) {
    signals.push(makeSignal("very_high_volume", "major", 12, `Volume is ${plan.volume_per_day} per day.`, "Reduce volume and prove consent first."));
  } else if (Number(plan.volume_per_day || 0) >= 600) {
    signals.push(makeSignal("elevated_volume", "minor", 6, `Volume is ${plan.volume_per_day} per day.`, "Use a warm-up plan and monitoring."));
  }

  if (sender.domain_alignment === "misaligned" || sender.identity_disclosure === "ambiguous") {
    signals.push(makeSignal("sender_identity_risk", "major", 14, "Sender identity or domain alignment is weak.", "Use a clearly disclosed sender and aligned domain."));
  } else if (sender.domain_alignment === "aligned" && sender.identity_disclosure === "clear") {
    signals.push(makeSignal("clear_sender_identity", "positive", -5, "Sender identity is clear and aligned.", "Keep disclosure visible."));
  }

  if (/\b(final notice|guaranteed|expires in|reply yes|inactive|urgent|act now|re:)\b/.test(copy)) {
    signals.push(makeSignal("deceptive_or_pressure_copy", "major", 14, "Copy uses urgency, thread hijacking, or unverifiable claims.", "Remove deceptive urgency and unsupported claims."));
  }

  if (/health|credit|debt|insurance|loan|immigration|employment/.test(copy)) {
    signals.push(makeSignal("sensitive_topic", "major", 10, "Copy references a sensitive topic.", "Apply stricter review and proof requirements."));
  }

  const riskScore = Math.max(0, Math.min(100, 18 + signals.reduce((sum, signal) => sum + signal.score_delta, 0)));
  const riskLevel = riskScore >= 70 ? "high" : riskScore >= 35 ? "medium" : "low";
  const verdict = riskScore >= 70 ? "block" : riskScore >= 35 ? "revise" : "allow";
  const confidence = Math.max(
    Number(campaign.minimum_confidence || 0),
    Math.min(0.96, 0.70 + Math.min(signals.length, 8) * 0.03),
  );

  const requiredFixes = signals
    .filter((signal) => signal.score_delta > 0)
    .sort((a, b) => b.score_delta - a.score_delta)
    .map((signal) => signal.fix)
    .filter((value, index, values) => values.indexOf(value) === index);

  return {
    verdict,
    riskScore,
    riskLevel,
    confidence: Number(confidence.toFixed(2)),
    signals,
    requiredFixes,
  };
}

function policyChecks(campaign, verdict) {
  const controls = campaign.controls || {};
  const recipient = campaign.recipient || {};
  const plan = campaign.campaign || {};
  const sender = campaign.sender || {};
  return [
    {
      id: "consent_basis",
      status: recipient.consent === "opt_in" ? "pass" : recipient.consent === "unknown" ? "warn" : "fail",
      detail: `consent=${recipient.consent || "missing"}`,
    },
    {
      id: "unsubscribe_for_commercial",
      status: !plan.commercial || controls.unsubscribe_link ? "pass" : "fail",
      detail: `commercial=${Boolean(plan.commercial)} unsubscribe=${Boolean(controls.unsubscribe_link)}`,
    },
    {
      id: "sender_identity",
      status: sender.domain_alignment === "aligned" && sender.identity_disclosure === "clear" ? "pass" : "warn",
      detail: `domain_alignment=${sender.domain_alignment || "missing"} identity=${sender.identity_disclosure || "missing"}`,
    },
    {
      id: "safe_to_send",
      status: verdict === "allow" ? "pass" : verdict === "revise" ? "warn" : "fail",
      detail: `verdict=${verdict}`,
    },
  ];
}

function validatePacket(packet, schema) {
  const checks = [
    { name: "declared_schema_id", passed: schema.$id === packet.schema, detail: schema.$id || "missing" },
    { name: "valid_verdict", passed: ["allow", "revise", "block"].includes(packet.review.verdict), detail: packet.review.verdict },
    { name: "risk_score_range", passed: Number.isInteger(packet.review.risk_score) && packet.review.risk_score >= 0 && packet.review.risk_score <= 100, detail: String(packet.review.risk_score) },
    { name: "signals_present", passed: Array.isArray(packet.signals) && packet.signals.length >= 3, detail: String(packet.signals.length) },
    { name: "policy_checks_present", passed: Array.isArray(packet.policy_checks) && packet.policy_checks.length >= 4, detail: String(packet.policy_checks.length) },
  ];
  return {
    valid: checks.every((check) => check.passed),
    engine: "declared-schema-required-field-checks-v1",
    checks,
  };
}

function main() {
  const inputs = readInputs();
  const caseInput = readJsonInput(inputs, "case_path", "case_json", "campaign");
  const schemaInput = readJsonInput(inputs, "schema_path", "schema_json", "schema");
  const caseBytes = caseInput.bytes;
  const schemaBytes = schemaInput.bytes;
  const campaign = caseInput.value;
  const schema = schemaInput.value;
  campaign.minimum_confidence = Number(inputs.minimum_confidence || 0.70);

  const result = analyze(campaign);
  const packet = {
    schema: "runx.spam_risk_review.result.v1",
    review: {
      case_id: campaign.id || path.basename(caseInput.locator),
      verdict: result.verdict,
      risk_score: result.riskScore,
      risk_level: result.riskLevel,
      confidence: result.confidence,
      summary: `${result.riskLevel} spam risk: ${result.verdict} before send.`,
      reviewer_action: result.verdict === "allow" ? "Campaign can proceed with recorded controls." : "Do not send until required fixes are completed.",
    },
    campaign: {
      channel: campaign.channel || "unknown",
      jurisdiction: campaign.jurisdiction || "unknown",
      purpose: campaign.campaign?.purpose || "unknown",
      commercial: Boolean(campaign.campaign?.commercial),
      volume_per_day: Number(campaign.campaign?.volume_per_day || 0),
      recipient_relationship: campaign.recipient?.relationship || "unknown",
      recipient_source: campaign.recipient?.source || "unknown",
    },
    signals: result.signals,
    policy_checks: policyChecks(campaign, result.verdict),
    required_fixes: result.requiredFixes,
    allow_conditions: result.verdict === "allow"
      ? ["Keep opt-in proof, unsubscribe handling, sender identity, and suppression controls attached to the send record."]
      : [],
    validation: {
      schema_id: schema.$id || "runx.spam_risk_review.result.v1",
      schema_sha256: sha256Bytes(schemaBytes),
      valid: false,
      engine: "declared-schema-required-field-checks-v1",
      checks: [],
    },
    provenance: {
      mode: "fixture",
      tool_version: TOOL_VERSION,
      case_path: caseInput.locator,
      case_sha256: sha256Bytes(caseBytes),
      output_payload_sha256: null,
    },
  };

  const outputPayload = {
    review: packet.review,
    campaign: packet.campaign,
    signals: packet.signals,
    policy_checks: packet.policy_checks,
    required_fixes: packet.required_fixes,
  };
  packet.provenance.output_payload_sha256 = sha256Text(canonicalJson(outputPayload));
  const validation = validatePacket(packet, schema);
  packet.validation.valid = validation.valid;
  packet.validation.engine = validation.engine;
  packet.validation.checks = validation.checks;
  if (!packet.validation.valid) {
    throw new Error(`spam risk review packet failed validation: ${JSON.stringify(validation.checks)}`);
  }

  packet.artifacts = [
    {
      id: packet.provenance.case_sha256,
      artifact_id: packet.provenance.case_sha256,
      type: "input_fixture",
      artifact_type: "input_fixture",
      label: packet.review.case_id,
    },
    {
      id: packet.validation.schema_sha256,
      artifact_id: packet.validation.schema_sha256,
      type: "json_schema",
      artifact_type: "json_schema",
      label: packet.validation.schema_id,
    },
    {
      id: packet.provenance.output_payload_sha256,
      artifact_id: packet.provenance.output_payload_sha256,
      type: "review_output",
      artifact_type: "review_output",
      label: "Spam risk review packet",
    },
  ];

  process.stdout.write(JSON.stringify(packet));
}

try {
  main();
} catch (error) {
  process.stderr.write(`${JSON.stringify({ error: { message: error.message } })}\n`);
  process.exitCode = 1;
}
