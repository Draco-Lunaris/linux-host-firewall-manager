import { useState, useEffect } from "react"
import {
  Box, Typography, Button, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Paper, Dialog, DialogTitle, DialogContent,
  DialogActions, TextField, MenuItem, FormControl, InputLabel, Select,
  Checkbox, FormControlLabel, Alert, IconButton, Tooltip, Chip,
} from "@mui/material"
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon, CheckCircle as CheckIcon, Warning as WarningIcon } from "@mui/icons-material"
import { rulesApi, type FirewallRule, type CreateRuleRequest, type ValidateRuleResponse } from "../api/client"

const ACTIONS = ["allow", "deny", "reject", "limit", "masquerade"]
const DIRECTIONS = ["in", "out", "forward"]
const PROTOCOLS = ["any", "tcp", "udp", "icmp", "icmpv6", "gre", "esp", "ah", "sctp"]

export default function RulesPage() {
  const [rules, setRules] = useState<FirewallRule[]>([])
  
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<FirewallRule | null>(null)
  const [validationResults, setValidationResults] = useState<Record<string, ValidateRuleResponse>>({})
  const [error, setError] = useState<string | null>(null)

  const loadRules = async () => {
    
    try {
      const resp = await rulesApi.list()
      setRules(resp.data.rules)
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to load rules")
    }
    
  }

  useEffect(() => { loadRules() }, [])

  const handleValidate = async (rule: FirewallRule) => {
    try {
      const resp = await rulesApi.validate(rule.id)
      setValidationResults({ ...validationResults, [rule.id]: resp.data })
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Validation failed")
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this rule?")) return
    try {
      await rulesApi.delete(id)
      loadRules()
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Delete failed")
    }
  }

  const handleClose = () => {
    setDialogOpen(false)
    setEditingRule(null)
    loadRules()
  }

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h4">Firewall Rules</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => { setEditingRule(null); setDialogOpen(true) }}>
          Create Rule
        </Button>
      </Box>
      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Direction</TableCell>
              <TableCell>Protocol</TableCell>
              <TableCell>Source</TableCell>
              <TableCell>Dest Port</TableCell>
              <TableCell>Priority</TableCell>
              <TableCell>Validation</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rules.map((rule) => {
              const v = validationResults[rule.id]
              return (
                <TableRow key={rule.id}>
                  <TableCell>{rule.name}</TableCell>
                  <TableCell><Chip label={rule.action} color={rule.action === "allow" ? "success" : rule.action === "deny" ? "error" : "default"} size="small" /></TableCell>
                  <TableCell>{rule.direction}</TableCell>
                  <TableCell>{rule.protocol}</TableCell>
                  <TableCell>{rule.src_cidr || "any"}</TableCell>
                  <TableCell>{rule.dst_port_start || "any"}{rule.dst_port_end && rule.dst_port_end !== rule.dst_port_start ? `-${rule.dst_port_end}` : ""}</TableCell>
                  <TableCell>{rule.priority}</TableCell>
                  <TableCell>
                    {v && (v.allowed ? (v.requires_approval ? <Tooltip title={v.reason}><WarningIcon color="warning" /></Tooltip> : <Tooltip title={v.reason}><CheckIcon color="success" /></Tooltip>) : <Tooltip title={v.reason}><WarningIcon color="error" /></Tooltip>)}
                    <Button size="small" onClick={() => handleValidate(rule)}>Check</Button>
                  </TableCell>
                  <TableCell>
                    <IconButton onClick={() => { setEditingRule(rule); setDialogOpen(true) }}><EditIcon /></IconButton>
                    <IconButton onClick={() => handleDelete(rule.id)}><DeleteIcon /></IconButton>
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </TableContainer>
      <RuleDialog open={dialogOpen} onClose={handleClose} editingRule={editingRule} />
    </Box>
  )
}

function RuleDialog({ open, onClose, editingRule }: { open: boolean; onClose: () => void; editingRule: FirewallRule | null }) {
  const [form, setForm] = useState<CreateRuleRequest>({
    name: "", description: "", action: "allow", direction: "in", protocol: "tcp",
    src_cidr: "", src_port_start: null, src_port_end: null, dst_cidr: "",
    dst_port_start: null, dst_port_end: null, interface_in: "", interface_out: "",
    comment: "", log: false, priority: 1000,
  })
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (editingRule) {
      setForm({
        name: editingRule.name, description: editingRule.description,
        action: editingRule.action, direction: editingRule.direction, protocol: editingRule.protocol,
        src_cidr: editingRule.src_cidr, src_port_start: editingRule.src_port_start, src_port_end: editingRule.src_port_end,
        dst_cidr: editingRule.dst_cidr, dst_port_start: editingRule.dst_port_start, dst_port_end: editingRule.dst_port_end,
        interface_in: editingRule.interface_in, interface_out: editingRule.interface_out,
        comment: editingRule.comment, log: editingRule.log, priority: editingRule.priority,
      })
    } else {
      setForm({ name: "", description: "", action: "allow", direction: "in", protocol: "tcp", src_cidr: "", src_port_start: null, src_port_end: null, dst_cidr: "", dst_port_start: null, dst_port_end: null, interface_in: "", interface_out: "", comment: "", log: false, priority: 1000 })
    }
  }, [editingRule, open])

  const handleSubmit = async () => {
    try {
      if (editingRule) {
        await rulesApi.update(editingRule.id, form)
      } else {
        await rulesApi.create(form)
      }
      onClose()
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to save rule")
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{editingRule ? "Edit Rule" : "Create Rule"}</DialogTitle>
      <DialogContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2, mt: 1 }}>
          <TextField label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} fullWidth required />
          <TextField label="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} fullWidth />
          <FormControl fullWidth><InputLabel>Action</InputLabel><Select value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value as FirewallRule["action"] })}>{ACTIONS.map(a => <MenuItem key={a} value={a}>{a}</MenuItem>)}</Select></FormControl>
          <FormControl fullWidth><InputLabel>Direction</InputLabel><Select value={form.direction} onChange={(e) => setForm({ ...form, direction: e.target.value as FirewallRule["direction"] })}>{DIRECTIONS.map(d => <MenuItem key={d} value={d}>{d}</MenuItem>)}</Select></FormControl>
          <FormControl fullWidth><InputLabel>Protocol</InputLabel><Select value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value as FirewallRule["protocol"] })}>{PROTOCOLS.map(p => <MenuItem key={p} value={p}>{p}</MenuItem>)}</Select></FormControl>
          <TextField label="Source CIDR" value={form.src_cidr || ""} onChange={(e) => setForm({ ...form, src_cidr: e.target.value || null })} placeholder="0.0.0.0/0" fullWidth />
          <TextField label="Source Port Start" type="number" value={form.src_port_start ?? ""} onChange={(e) => setForm({ ...form, src_port_start: e.target.value ? Number(e.target.value) : null })} fullWidth />
          <TextField label="Source Port End" type="number" value={form.src_port_end ?? ""} onChange={(e) => setForm({ ...form, src_port_end: e.target.value ? Number(e.target.value) : null })} fullWidth />
          <TextField label="Dest CIDR" value={form.dst_cidr || ""} onChange={(e) => setForm({ ...form, dst_cidr: e.target.value || null })} fullWidth />
          <TextField label="Dest Port Start" type="number" value={form.dst_port_start ?? ""} onChange={(e) => setForm({ ...form, dst_port_start: e.target.value ? Number(e.target.value) : null })} fullWidth />
          <TextField label="Dest Port End" type="number" value={form.dst_port_end ?? ""} onChange={(e) => setForm({ ...form, dst_port_end: e.target.value ? Number(e.target.value) : null })} fullWidth />
          <TextField label="Interface In" value={form.interface_in || ""} onChange={(e) => setForm({ ...form, interface_in: e.target.value || null })} fullWidth />
          <TextField label="Interface Out" value={form.interface_out || ""} onChange={(e) => setForm({ ...form, interface_out: e.target.value || null })} fullWidth />
          <TextField label="Comment" value={form.comment} onChange={(e) => setForm({ ...form, comment: e.target.value })} fullWidth />
          <TextField label="Priority" type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} fullWidth />
          <FormControlLabel control={<Checkbox checked={form.log} onChange={(e) => setForm({ ...form, log: e.target.checked })} />} label="Log" />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={!form.name}>{editingRule ? "Update" : "Create"}</Button>
      </DialogActions>
    </Dialog>
  )
}
