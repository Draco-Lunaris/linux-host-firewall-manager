import { useState, useEffect } from "react"
import {
  Box, Typography, Button, Paper, Dialog, DialogTitle, DialogContent,
  DialogActions, TextField, Alert, IconButton, Accordion, AccordionSummary,
  AccordionDetails, List, ListItem, ListItemText, ListItemSecondaryAction,
  Chip, Divider, MenuItem, Select, FormControl, InputLabel,
} from "@mui/material"
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon, ExpandMore as ExpandMoreIcon, Code as CodeIcon, DragHandle as DragHandleIcon } from "@mui/icons-material"
import {
  DndContext, closestCenter, PointerSensor, useSensor, useSensors, type DragEndEvent,
} from "@dnd-kit/core"
import {
  SortableContext, arrayMove, useSortable, verticalListSortingStrategy,
} from "@dnd-kit/sortable"
import { CSS } from "@dnd-kit/utilities"
import {
  policySetsApi, ruleGroupsApi,
  type FirewallPolicySet, type PolicySetRuleGroup, type FirewallRuleGroup,
  type PreviewCompilationResponse, type DefaultPolicyValue,
} from "../api/client"

export default function PolicySetsPage() {
  const [policySets, setPolicySets] = useState<FirewallPolicySet[]>([])
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingSet, setEditingSet] = useState<FirewallPolicySet | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      const resp = await policySetsApi.list()
      setPolicySets(resp.data.policy_sets)
    } catch (e: unknown) {
      setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to load policy sets")
    }
  }

  useEffect(() => { load() }, [])

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this policy set?")) return
    try { await policySetsApi.delete(id); load() } catch (e: unknown) { setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message ?? null) }
  }

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h4">Policy Sets</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => { setEditingSet(null); setDialogOpen(true) }}>
          Create Policy Set
        </Button>
      </Box>
      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}
      {policySets.map((ps) => (
        <PolicySetAccordion key={ps.id} policySet={ps} onEdit={() => { setEditingSet(ps); setDialogOpen(true) }} onDelete={() => handleDelete(ps.id)} />
      ))}
      <PolicySetDialog open={dialogOpen} onClose={() => { setDialogOpen(false); setEditingSet(null); load() }} editingSet={editingSet} />
    </Box>
  )
}

function PolicySetAccordion({ policySet, onEdit, onDelete }: { policySet: FirewallPolicySet; onEdit: () => void; onDelete: () => void }) {
  const [groups, setGroups] = useState<PolicySetRuleGroup[]>([])
  const [allGroups, setAllGroups] = useState<FirewallRuleGroup[]>([])
  const [preview, setPreview] = useState<PreviewCompilationResponse | null>(null)
  const [expanded, setExpanded] = useState(false)
  const [savingOrder, setSavingOrder] = useState(false)
  const [addGroupId, setAddGroupId] = useState("")

  const loadGroups = async () => {
    try {
      const [setResp, allResp] = await Promise.all([policySetsApi.listGroups(policySet.id), ruleGroupsApi.list()])
      setGroups(setResp.data.rule_groups)
      setAllGroups(allResp.data.rule_groups)
    } catch { /* transient */ }
  }

  const handlePreview = async () => {
    try {
      const resp = await policySetsApi.preview(policySet.id)
      setPreview(resp.data)
    } catch (e: unknown) {
      alert((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Preview failed")
    }
  }

  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 5 } }))

  const handleDragEnd = (event: DragEndEvent) => {
    const { active, over } = event
    if (!over || active.id === over.id) return
    setGroups((items) => {
      const oldIndex = items.findIndex((g) => g.rule_group_id === active.id)
      const newIndex = items.findIndex((g) => g.rule_group_id === over.id)
      if (oldIndex < 0 || newIndex < 0) return items
      return arrayMove(items, oldIndex, newIndex)
    })
  }

  const saveOrder = async () => {
    setSavingOrder(true)
    try {
      await policySetsApi.reorderGroups(policySet.id, groups.map((g) => g.rule_group_id))
      loadGroups()
    } catch (e: unknown) {
      alert((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to save order")
    } finally {
      setSavingOrder(false)
    }
  }

  const handleAdd = async () => {
    if (!addGroupId) return
    try {
      await policySetsApi.addGroup(policySet.id, addGroupId)
      setAddGroupId("")
      loadGroups()
    } catch (e: unknown) {
      alert((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to add group")
    }
  }

  const handleRemove = async (groupId: string) => {
    try {
      await policySetsApi.removeGroup(policySet.id, groupId)
      loadGroups()
    } catch (e: unknown) {
      alert((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to remove group")
    }
  }

  useEffect(() => { if (expanded) loadGroups() }, [expanded]) // eslint-disable-line react-hooks/exhaustive-deps

  const availableToAdd = allGroups.filter((g) => !groups.some((sg) => sg.rule_group_id === g.id))

  return (
    <Accordion expanded={expanded} onChange={() => setExpanded(!expanded)} sx={{ mb: 1 }}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
          <Typography variant="h6">{policySet.name}</Typography>
          <Chip label={`${groups.length} rule groups`} size="small" />
          <Chip
            label={`in: ${policySet.default_input_policy ?? "system"}`}
            size="small"
            variant="outlined"
          />
          <Chip
            label={`out: ${policySet.default_output_policy ?? "system"}`}
            size="small"
            variant="outlined"
          />
          <Box sx={{ flexGrow: 1 }} />
          <IconButton onClick={(e) => { e.stopPropagation(); onEdit() }}><EditIcon /></IconButton>
          <IconButton onClick={(e) => { e.stopPropagation(); onDelete() }}><DeleteIcon /></IconButton>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>{policySet.description}</Typography>
        <Button startIcon={<CodeIcon />} onClick={handlePreview} sx={{ mb: 2 }}>Preview as Commands</Button>
        {preview && (
          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle2">UFW Commands ({preview.ufw_commands.length}):</Typography>
            <Paper sx={{ p: 1, mb: 1, bgcolor: "background.default", maxHeight: 200, overflow: "auto" }}>
              {preview.ufw_commands.map((cmd, i) => <Typography key={i} variant="body2" sx={{ fontFamily: "monospace" }}>{cmd}</Typography>)}
            </Paper>
            <Typography variant="subtitle2">firewalld Commands ({preview.firewalld_commands.length}):</Typography>
            <Paper sx={{ p: 1, bgcolor: "background.default", maxHeight: 200, overflow: "auto" }}>
              {preview.firewalld_commands.map((cmd, i) => <Typography key={i} variant="body2" sx={{ fontFamily: "monospace" }}>{cmd}</Typography>)}
            </Paper>
          </Box>
        )}
        <Divider sx={{ mb: 2 }} />
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="subtitle2">Rule Groups (drag to reorder apply order)</Typography>
          {groups.length > 1 && (
            <Button size="small" variant="outlined" disabled={savingOrder} onClick={saveOrder}>
              {savingOrder ? "Saving..." : "Save Order"}
            </Button>
          )}
        </Box>
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
          <SortableContext items={groups.map((g) => g.rule_group_id)} strategy={verticalListSortingStrategy}>
            <List>
              {groups.map((g) => (
                <SortableGroupItem key={g.rule_group_id} group={g} onRemove={() => handleRemove(g.rule_group_id)} />
              ))}
            </List>
          </SortableContext>
        </DndContext>
        {groups.length === 0 && <Typography color="textSecondary" sx={{ mb: 1 }}>No rule groups in this policy set</Typography>}
        <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
          <FormControl fullWidth size="small">
            <InputLabel>Add rule group</InputLabel>
            <Select value={addGroupId} label="Add rule group" onChange={(e) => setAddGroupId(e.target.value)}>
              {availableToAdd.length === 0 && <MenuItem disabled value="">All groups already added</MenuItem>}
              {availableToAdd.map((g) => (
                <MenuItem key={g.id} value={g.id}>{g.name} ({g.rule_count} rules)</MenuItem>
              ))}
            </Select>
          </FormControl>
          <Button variant="contained" startIcon={<AddIcon />} onClick={handleAdd} disabled={!addGroupId}>Add</Button>
        </Box>
      </AccordionDetails>
    </Accordion>
  )
}

function PolicySetDialog({ open, onClose, editingSet }: { open: boolean; onClose: () => void; editingSet: FirewallPolicySet | null }) {
  // "" is the UI sentinel for "System default" (null at the API). The other
  // values map to the firewall_default_policy enum.
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [defaultInput, setDefaultInput] = useState<string>("")
  const [defaultOutput, setDefaultOutput] = useState<string>("")
  // Track the prefill so update can OMIT unchanged default fields (a sent null
  // would otherwise clear them). name/description are always sent (COALESCE).
  const [initialInput, setInitialInput] = useState<string>("")
  const [initialOutput, setInitialOutput] = useState<string>("")
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (editingSet) {
      setName(editingSet.name)
      setDescription(editingSet.description)
      const i = editingSet.default_input_policy ?? ""
      const o = editingSet.default_output_policy ?? ""
      setDefaultInput(i); setInitialInput(i)
      setDefaultOutput(o); setInitialOutput(o)
    } else {
      setName(""); setDescription("")
      setDefaultInput(""); setInitialInput("")
      setDefaultOutput(""); setInitialOutput("")
    }
  }, [editingSet, open])

  const uiToVal = (v: string): DefaultPolicyValue => (v === "" ? null : (v as "allow" | "deny" | "reject"))

  const handleSubmit = async () => {
    try {
      if (editingSet) {
        const payload: Parameters<typeof policySetsApi.update>[1] = { name, description }
        if (defaultInput !== initialInput) payload.default_input_policy = uiToVal(defaultInput)
        if (defaultOutput !== initialOutput) payload.default_output_policy = uiToVal(defaultOutput)
        await policySetsApi.update(editingSet.id, payload)
      } else {
        await policySetsApi.create({
          name,
          description,
          default_input_policy: uiToVal(defaultInput),
          default_output_policy: uiToVal(defaultOutput),
        })
      }
      onClose()
    } catch (e: unknown) { setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to save") }
  }

  const policyOptions = [
    { value: "", label: "System default" },
    { value: "allow", label: "allow" },
    { value: "deny", label: "deny" },
    { value: "reject", label: "reject" },
  ]

  return (
    <Dialog open={open} onClose={onClose} fullWidth>
      <DialogTitle>{editingSet ? "Edit Policy Set" : "Create Policy Set"}</DialogTitle>
      <DialogContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} fullWidth sx={{ mt: 1 }} required />
        <TextField label="Description" value={description} onChange={(e) => setDescription(e.target.value)} fullWidth sx={{ mt: 2 }} />
        <FormControl fullWidth sx={{ mt: 2 }}>
          <InputLabel>Default incoming policy</InputLabel>
          <Select label="Default incoming policy" value={defaultInput} onChange={(e) => setDefaultInput(e.target.value)}>
            {policyOptions.map((o) => <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>)}
          </Select>
        </FormControl>
        <FormControl fullWidth sx={{ mt: 2 }}>
          <InputLabel>Default outgoing policy</InputLabel>
          <Select label="Default outgoing policy" value={defaultOutput} onChange={(e) => setDefaultOutput(e.target.value)}>
            {policyOptions.map((o) => <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>)}
          </Select>
        </FormControl>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={!name}>{editingSet ? "Update" : "Create"}</Button>
      </DialogActions>
    </Dialog>
  )
}

function SortableGroupItem({ group, onRemove }: { group: PolicySetRuleGroup; onRemove: () => void }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: group.rule_group_id })
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
      <ListItemText primary={group.name} secondary={group.description} />
      <ListItemSecondaryAction>
        <Chip label={`${group.rule_count} rules`} size="small" sx={{ mr: 1 }} />
        <IconButton size="small" onClick={onRemove}><DeleteIcon fontSize="small" /></IconButton>
      </ListItemSecondaryAction>
    </ListItem>
  )
}