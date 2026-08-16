import { useState, useEffect } from "react"
import {
  Box, Typography, Button, Dialog, DialogTitle, DialogContent,
  DialogActions, TextField, Alert, IconButton, Accordion, AccordionSummary,
  AccordionDetails, List, ListItem, ListItemText, ListItemSecondaryAction,
  Chip, Divider, FormControl, InputLabel, Select, MenuItem, Checkbox,
  FormControlLabel, Tooltip,
} from "@mui/material"
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon, ExpandMore as ExpandMoreIcon, DragHandle as DragHandleIcon, Warning as WarningIcon } from "@mui/icons-material"
import {
  DndContext, closestCenter, PointerSensor, useSensor, useSensors, type DragEndEvent,
} from "@dnd-kit/core"
import {
  SortableContext, arrayMove, useSortable, verticalListSortingStrategy,
} from "@dnd-kit/sortable"
import { CSS } from "@dnd-kit/utilities"
import { ruleGroupsApi, rulesApi, type FirewallRule, type FirewallRuleGroup, type CreateRuleRequest } from "../api/client"

const ACTIONS = ["allow", "deny", "reject", "limit", "masquerade"]
const DIRECTIONS = ["in", "out", "forward"]
const PROTOCOLS = ["any", "tcp", "udp", "icmp", "icmpv6", "gre", "esp", "ah", "sctp"]

/** Mirrors fw_core::policy::check_rule — broad allow (any src + any dst port) is flagged. */
function isFlagged(rule: FirewallRule): boolean {
  if (rule.action !== "allow") return false
  const broadSrc = !rule.src_cidr || rule.src_cidr === "0.0.0.0/0" || rule.src_cidr === "::/0" || rule.src_cidr === "any"
  const broadPort = rule.dst_port_start === null && rule.dst_port_end === null
  return broadSrc && broadPort
}

export default function RuleGroupsPage() {
  const [groups, setGroups] = useState<FirewallRuleGroup[]>([])
  const [groupDialogOpen, setGroupDialogOpen] = useState(false)
  const [editingGroup, setEditingGroup] = useState<FirewallRuleGroup | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      const resp = await ruleGroupsApi.list()
      setGroups(resp.data.rule_groups)
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to load rule groups")
    }
  }

  useEffect(() => { load() }, [])

  const handleDeleteGroup = async (g: FirewallRuleGroup) => {
    if (g.used_by_count > 0) {
      setError(`"${g.name}" is used by ${g.used_by_count} policy set(s); remove it from those sets before deleting`)
      return
    }
    if (!confirm(`Delete rule group "${g.name}" and all ${g.rule_count} rule(s) in it?`)) return
    try {
      await ruleGroupsApi.delete(g.id)
      load()
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Delete failed")
    }
  }

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h4">Rule Groups</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => { setEditingGroup(null); setGroupDialogOpen(true) }}>
          Create Rule Group
        </Button>
      </Box>
      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}
      {groups.length === 0 && <Typography color="textSecondary">No rule groups yet. Create one, then add rules to it.</Typography>}
      {groups.map((g) => (
        <RuleGroupAccordion
          key={g.id}
          group={g}
          onEdit={() => { setEditingGroup(g); setGroupDialogOpen(true) }}
          onDelete={() => handleDeleteGroup(g)}
          onChanged={load}
          onError={setError}
        />
      ))}
      <GroupDialog open={groupDialogOpen} onClose={() => { setGroupDialogOpen(false); setEditingGroup(null); load() }} editingGroup={editingGroup} />
    </Box>
  )
}

function RuleGroupAccordion({
  group, onEdit, onDelete, onChanged, onError,
}: {
  group: FirewallRuleGroup
  onEdit: () => void
  onDelete: () => void
  onChanged: () => void
  onError: (msg: string | null) => void
}) {
  const [rules, setRules] = useState<FirewallRule[]>([])
  const [expanded, setExpanded] = useState(false)
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<FirewallRule | null>(null)
  const [savingOrder, setSavingOrder] = useState(false)

  const loadRules = async () => {
    try {
      const resp = await ruleGroupsApi.listRules(group.id)
      setRules(resp.data.rules)
    } catch {
      /* keep prior list on transient error */
    }
  }

  useEffect(() => { if (expanded) loadRules() }, [expanded]) // eslint-disable-line react-hooks/exhaustive-deps

  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 5 } }))

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event
    if (!over || active.id === over.id) return
    setRules((items) => {
      const oldIndex = items.findIndex((r) => r.id === active.id)
      const newIndex = items.findIndex((r) => r.id === over.id)
      if (oldIndex < 0 || newIndex < 0) return items
      return arrayMove(items, oldIndex, newIndex)
    })
  }

  const saveOrder = async () => {
    setSavingOrder(true)
    try {
      await ruleGroupsApi.reorder(group.id, rules.map((r) => r.id))
    } catch (e: unknown) {
      onError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to save order")
    } finally {
      setSavingOrder(false)
    }
  }

  const handleDeleteRule = async (rule: FirewallRule) => {
    if (!confirm(`Delete rule "${rule.name}"?`)) return
    try {
      await rulesApi.delete(rule.id)
      loadRules()
      onChanged()
    } catch (e: unknown) {
      onError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Delete failed")
    }
  }

  return (
    <Accordion expanded={expanded} onChange={() => setExpanded(!expanded)} sx={{ mb: 1 }}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
          <Typography variant="h6">{group.name}</Typography>
          <Chip label={`${group.rule_count} rules`} size="small" />
          <Chip label={`used by ${group.used_by_count} set(s)`} size="small" color={group.used_by_count > 0 ? "primary" : "default"} variant={group.used_by_count > 0 ? "filled" : "outlined"} />
          <Box sx={{ flexGrow: 1 }} />
          <IconButton onClick={(e) => { e.stopPropagation(); onEdit() }}><EditIcon /></IconButton>
          <IconButton onClick={(e) => { e.stopPropagation(); onDelete() }}><DeleteIcon /></IconButton>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>{group.description}</Typography>
        <Divider sx={{ mb: 2 }} />
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2">Rules (drag to reorder within the group)</Typography>
          <Box sx={{ display: "flex", gap: 1 }}>
            {rules.length > 1 && (
              <Button size="small" variant="outlined" disabled={savingOrder} onClick={saveOrder}>
                {savingOrder ? "Saving..." : "Save Order"}
              </Button>
            )}
            <Button size="small" variant="contained" startIcon={<AddIcon />} onClick={() => { setEditingRule(null); setRuleDialogOpen(true) }}>
              Add Rule
            </Button>
          </Box>
        </Box>
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
          <SortableContext items={rules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
            <List>
              {rules.map((rule) => (
                <SortableRuleItem key={rule.id} rule={rule} onEdit={() => { setEditingRule(rule); setRuleDialogOpen(true) }} onDelete={() => handleDeleteRule(rule)} />
              ))}
            </List>
          </SortableContext>
        </DndContext>
        {rules.length === 0 && <Typography color="textSecondary">No rules in this group yet</Typography>}
        <RuleDialog
          open={ruleDialogOpen}
          onClose={() => { setRuleDialogOpen(false); setEditingRule(null); loadRules(); onChanged() }}
          groupId={group.id}
          editingRule={editingRule}
          onError={onError}
        />
      </AccordionDetails>
    </Accordion>
  )
}

function GroupDialog({ open, onClose, editingGroup }: { open: boolean; onClose: () => void; editingGroup: FirewallRuleGroup | null }) {
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (editingGroup) { setName(editingGroup.name); setDescription(editingGroup.description) }
    else { setName(""); setDescription("") }
  }, [editingGroup, open])

  const handleSubmit = async () => {
    try {
      if (editingGroup) { await ruleGroupsApi.update(editingGroup.id, { name, description }) }
      else { await ruleGroupsApi.create({ name, description }) }
      onClose()
    } catch (e: unknown) { setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to save") }
  }

  return (
    <Dialog open={open} onClose={onClose} fullWidth>
      <DialogTitle>{editingGroup ? "Edit Rule Group" : "Create Rule Group"}</DialogTitle>
      <DialogContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} fullWidth sx={{ mt: 1 }} required />
        <TextField label="Description" value={description} onChange={(e) => setDescription(e.target.value)} fullWidth sx={{ mt: 2 }} />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={!name}>{editingGroup ? "Update" : "Create"}</Button>
      </DialogActions>
    </Dialog>
  )
}

function SortableRuleItem({ rule, onEdit, onDelete }: { rule: FirewallRule; onEdit: () => void; onDelete: () => void }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: rule.id })
  const flagged = isFlagged(rule)
  return (
    <ListItem
      ref={setNodeRef}
      sx={{
        transform: CSS.Transform.toString(transform),
        transition,
        zIndex: isDragging ? 1 : "auto",
        bgcolor: isDragging ? "action.hover" : "transparent",
        border: "1px solid",
        borderColor: "divider",
        borderRadius: 1,
        mb: 0.5,
      }}
    >
      <IconButton {...attributes} {...listeners} size="small" sx={{ cursor: "grab", mr: 1 }}>
        <DragHandleIcon fontSize="small" />
      </IconButton>
      <ListItemText
        primary={
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <span>{rule.name}</span>
            {flagged && (
              <Tooltip title="Broad allow rule — requires admin approval to assign (SEC-003)">
                <WarningIcon color="warning" fontSize="small" />
              </Tooltip>
            )}
          </Box>
        }
        secondary={`${rule.action} ${rule.direction} ${rule.protocol} ${rule.src_cidr || "any"} → ${rule.dst_port_start || "any"}`}
      />
      <ListItemSecondaryAction>
        <Chip label={rule.action} size="small" color={rule.action === "allow" ? "success" : rule.action === "deny" ? "error" : "default"} sx={{ mr: 1 }} />
        <IconButton size="small" onClick={onEdit}><EditIcon fontSize="small" /></IconButton>
        <IconButton size="small" onClick={onDelete}><DeleteIcon fontSize="small" /></IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  )
}

function RuleDialog({
  open, onClose, groupId, editingRule, onError,
}: {
  open: boolean
  onClose: () => void
  groupId: string
  editingRule: FirewallRule | null
  onError: (msg: string | null) => void
}) {
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
        await ruleGroupsApi.createRule(groupId, form)
      }
      onClose()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to save rule"
      setError(msg)
      onError(msg)
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{editingRule ? "Edit Rule" : "Create Rule in Group"}</DialogTitle>
      <DialogContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2, mt: 1 }}>
          <TextField label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} fullWidth required />
          <TextField label="Description" value={form.description || ""} onChange={(e) => setForm({ ...form, description: e.target.value })} fullWidth />
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
          <TextField label="Comment" value={form.comment || ""} onChange={(e) => setForm({ ...form, comment: e.target.value })} fullWidth />
          <TextField label="Priority" type="number" value={form.priority ?? 1000} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} fullWidth />
          <FormControlLabel control={<Checkbox checked={form.log || false} onChange={(e) => setForm({ ...form, log: e.target.checked })} />} label="Log" />
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={!form.name}>{editingRule ? "Update" : "Create"}</Button>
      </DialogActions>
    </Dialog>
  )
}