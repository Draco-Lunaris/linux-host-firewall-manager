import { useState, useEffect } from "react"
import {
  Box, Typography, Button, Paper, Alert, Checkbox,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  CircularProgress, Stepper, Step, StepLabel,
  Dialog, DialogTitle, DialogContent,
} from "@mui/material"
import { RocketLaunch as DeployIcon, Preview as PreviewIcon, RemoveCircleOutline as UnassignIcon } from "@mui/icons-material"
import { policySetsApi, deploymentApi, hostsApi, apiClient, type FirewallPolicySet, type DeploymentPreviewResponse } from "../api/client"
import type { Group } from "../types"

interface HostInfo {
  id: string
  fqdn: string
  ip_address: string
  health_status: string
  backend_active?: string
  os_family?: string
}

export default function DeploymentPage() {
  const [policySets, setPolicySets] = useState<FirewallPolicySet[]>([])
  const [hosts, setHosts] = useState<HostInfo[]>([])
  const [groups, setGroups] = useState<Group[]>([])
  const [selectedPolicySet, setSelectedPolicySet] = useState<string>("")
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set())
  const [selectedGroups, setSelectedGroups] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<DeploymentPreviewResponse | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)

  useEffect(() => {
    const load = async () => {
      try {
        const [psResp, hostResp, groupResp] = await Promise.all([
          policySetsApi.list(),
          hostsApi.list(),
          apiClient.get<Group[]>("/groups"),
        ])
        setPolicySets(psResp.data.policy_sets)
        // /hosts returns { hosts, total } — read the array.
        setHosts(hostResp.data?.hosts ?? [])
        setGroups(groupResp.data ?? [])
      } catch (e: unknown) {
        setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to load data")
      }
    }
    load()
  }, [])

  const toggleHost = (id: string) => {
    const next = new Set(selectedHosts)
    if (next.has(id)) next.delete(id); else next.add(id)
    setSelectedHosts(next)
  }
  const toggleGroup = (id: string) => {
    const next = new Set(selectedGroups)
    if (next.has(id)) next.delete(id); else next.add(id)
    setSelectedGroups(next)
  }

  const hasTargets = selectedHosts.size > 0 || selectedGroups.size > 0
  const targetHostIds = () => Array.from(selectedHosts)
  const targetGroupIds = () => Array.from(selectedGroups)

  const handleAssign = async () => {
    if (!selectedPolicySet || !hasTargets) return
    setBusy(true); setError(null); setResult(null)
    try {
      const resp = await deploymentApi.assign(selectedPolicySet, targetHostIds(), targetGroupIds())
      setResult(`Policy set assigned to ${resp.data.assigned_count} host(s). They will pull and apply it on their next check-in.`)
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Assignment failed")
    }
    setBusy(false)
  }

  const handleUnassign = async () => {
    if (!selectedPolicySet || !hasTargets) return
    setBusy(true); setError(null); setResult(null)
    try {
      const resp = await deploymentApi.unassign(selectedPolicySet, targetHostIds(), targetGroupIds())
      setResult(`Policy set removed from ${resp.data.unassigned_from} host(s).`)
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Unassign failed")
    }
    setBusy(false)
  }

  const handlePreview = async () => {
    if (!selectedPolicySet) return
    setPreviewLoading(true); setError(null)
    try {
      const resp = await deploymentApi.preview(selectedPolicySet)
      setPreview(resp.data)
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Preview failed")
    }
    setPreviewLoading(false)
  }

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>Deploy Policy Set</Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}
      {result && <Alert severity="success" sx={{ mb: 2 }}>{result}</Alert>}

      <Stepper sx={{ mb: 3 }}>
        <Step completed={!!selectedPolicySet}><StepLabel>Select Policy Set</StepLabel></Step>
        <Step completed={hasTargets}><StepLabel>Select Targets</StepLabel></Step>
        <Step completed={!!result}><StepLabel>Assign</StepLabel></Step>
      </Stepper>

      <Box sx={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 2 }}>
        <Box>
          <Typography variant="h6" sx={{ mb: 1 }}>1. Select Policy Set</Typography>
          <Paper sx={{ p: 1 }}>
            {policySets.map((ps) => (
              <Box key={ps.id} sx={{ p: 1, cursor: "pointer", bgcolor: selectedPolicySet === ps.id ? "action.selected" : "transparent", borderRadius: 1 }}
                onClick={() => setSelectedPolicySet(ps.id)}>
                <Typography variant="body1">{ps.name}</Typography>
                <Typography variant="body2" color="textSecondary">{ps.description}</Typography>
              </Box>
            ))}
          </Paper>
        </Box>

        <Box>
          <Typography variant="h6" sx={{ mb: 1 }}>2. Select Hosts ({selectedHosts.size}) &amp; Groups ({selectedGroups.size})</Typography>
          {groups.length > 0 && (
            <Paper sx={{ p: 1, mb: 1 }}>
              <Typography variant="body2" color="textSecondary" sx={{ mb: 0.5 }}>Groups</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {groups.map((g) => (
                  <Button
                    key={g.id} size="small" variant={selectedGroups.has(g.id) ? "contained" : "outlined"}
                    onClick={() => toggleGroup(g.id)}
                  >
                    {g.name}
                  </Button>
                ))}
              </Box>
            </Paper>
          )}
          <TableContainer component={Paper} sx={{ maxHeight: 400, overflow: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell padding="checkbox"></TableCell>
                  <TableCell>FQDN</TableCell>
                  <TableCell>IP</TableCell>
                  <TableCell>Backend</TableCell>
                  <TableCell>Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {hosts.map((host) => (
                  <TableRow key={host.id} hover onClick={() => toggleHost(host.id)}>
                    <TableCell padding="checkbox"><Checkbox checked={selectedHosts.has(host.id)} /></TableCell>
                    <TableCell>{host.fqdn}</TableCell>
                    <TableCell>{host.ip_address}</TableCell>
                    <TableCell>{host.backend_active || host.os_family || "—"}</TableCell>
                    <TableCell>{host.health_status}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      </Box>

      <Box sx={{ mt: 2, display: "flex", gap: 2 }}>
        <Button variant="outlined" startIcon={previewLoading ? <CircularProgress size={20} /> : <PreviewIcon />}
          disabled={!selectedPolicySet || previewLoading} onClick={handlePreview}>
          Preview
        </Button>
        <Button variant="contained" startIcon={busy ? <CircularProgress size={20} /> : <DeployIcon />}
          disabled={!selectedPolicySet || !hasTargets || busy} onClick={handleAssign}>
          {busy ? "Assigning..." : "Assign"}
        </Button>
        <Button variant="outlined" color="error" startIcon={<UnassignIcon />}
          disabled={!selectedPolicySet || !hasTargets || busy} onClick={handleUnassign}>
          Unassign
        </Button>
      </Box>

      <Dialog open={!!preview} onClose={() => setPreview(null)} maxWidth="md" fullWidth>
        <DialogTitle>Policy Set Preview{preview ? ` — ${preview.rule_count} rule${preview.rule_count !== 1 ? "s" : ""}` : ""}</DialogTitle>
        <DialogContent>
          {preview && (
            <Box>
              <Typography variant="subtitle2" sx={{ mt: 1 }}>UFW commands</Typography>
              <Paper variant="outlined" sx={{ p: 1, fontFamily: "monospace", fontSize: "0.8rem", whiteSpace: "pre-wrap" }}>
                {preview.ufw_command.length ? preview.ufw_command.join("\n") : "(none)"}
              </Paper>
              <Typography variant="subtitle2" sx={{ mt: 2 }}>firewalld commands</Typography>
              <Paper variant="outlined" sx={{ p: 1, fontFamily: "monospace", fontSize: "0.8rem", whiteSpace: "pre-wrap" }}>
                {preview.firewalld_command.length ? preview.firewalld_command.join("\n") : "(none)"}
              </Paper>
            </Box>
          )}
        </DialogContent>
      </Dialog>
    </Box>
  )
}