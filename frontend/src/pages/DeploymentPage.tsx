import { useState, useEffect } from "react"
import {
  Box, Typography, Button, Paper, Alert, Checkbox,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  CircularProgress, Stepper, Step, StepLabel,
} from "@mui/material"
import { RocketLaunch as DeployIcon, Preview as PreviewIcon } from "@mui/icons-material"
import { policySetsApi, deploymentApi, type FirewallPolicySet } from "../api/client"
import { hostsApi } from "../api/client"

export default function DeploymentPage() {
  const [policySets, setPolicySets] = useState<FirewallPolicySet[]>([])
  const [hosts, setHosts] = useState<any[]>([])
  const [selectedPolicySet, setSelectedPolicySet] = useState<string>("")
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set())
  const [deploying, setDeploying] = useState(false)
  const [result, setResult] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const load = async () => {
      try {
        const [psResp, hostResp] = await Promise.all([
          policySetsApi.list(),
          hostsApi.list(),
        ])
        setPolicySets(psResp.data.policy_sets)
        setHosts(hostResp.data)
      } catch (e: any) {
        setError(e.response?.data?.error?.message || "Failed to load data")
      }
    }
    load()
  }, [])

  const toggleHost = (id: string) => {
    const next = new Set(selectedHosts)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelectedHosts(next)
  }

  const handleDeploy = async () => {
    if (!selectedPolicySet || selectedHosts.size === 0) return
    setDeploying(true)
    setError(null)
    setResult(null)
    try {
      const resp = await deploymentApi.deploy(selectedPolicySet, Array.from(selectedHosts), true)
      setResult(`Job ${resp.data.job_id} created for ${resp.data.host_count} hosts. Status: ${resp.data.status}`)
    } catch (e: any) {
      setError(e.response?.data?.error?.message || "Deploy failed")
    }
    setDeploying(false)
  }

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>Deploy Policy Set</Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}
      {result && <Alert severity="success" sx={{ mb: 2 }}>{result}</Alert>}

      <Stepper sx={{ mb: 3 }}>
        <Step completed={!!selectedPolicySet}><StepLabel>Select Policy Set</StepLabel></Step>
        <Step completed={selectedHosts.size > 0}><StepLabel>Select Hosts</StepLabel></Step>
        <Step completed={!!result}><StepLabel>Deploy</StepLabel></Step>
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
          <Typography variant="h6" sx={{ mb: 1 }}>2. Select Hosts ({selectedHosts.size} selected)</Typography>
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
        <Button variant="outlined" startIcon={<PreviewIcon />} disabled={!selectedPolicySet || selectedHosts.size === 0}>
          Preview (Dry Run)
        </Button>
        <Button variant="contained" startIcon={deploying ? <CircularProgress size={20} /> : <DeployIcon />}
          disabled={!selectedPolicySet || selectedHosts.size === 0 || deploying} onClick={handleDeploy}>
          {deploying ? "Deploying..." : "Deploy Now"}
        </Button>
      </Box>
    </Box>
  )
}
