import { useState, useEffect } from "react"
import {
  Box, Typography, Button, Paper, Dialog, DialogTitle, DialogContent,
  DialogActions, TextField, Alert, IconButton, Accordion, AccordionSummary,
  AccordionDetails, List, ListItem, ListItemText, ListItemSecondaryAction,
  Chip, Divider,
} from "@mui/material"
import { Add as AddIcon, Edit as EditIcon, Delete as DeleteIcon, ExpandMore as ExpandMoreIcon, Code as CodeIcon, DragHandle as DragHandleIcon } from "@mui/icons-material"
import {
  DndContext, closestCenter, PointerSensor, useSensor, useSensors, type DragEndEvent,
} from "@dnd-kit/core"
import {
  SortableContext, arrayMove, useSortable, verticalListSortingStrategy,
} from "@dnd-kit/sortable"
import { CSS } from "@dnd-kit/utilities"
import { policySetsApi, type FirewallPolicySet, type FirewallRule, type PreviewCompilationResponse } from "../api/client"

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
  const [rules, setRules] = useState<FirewallRule[]>([])
  const [preview, setPreview] = useState<PreviewCompilationResponse | null>(null)
  const [expanded, setExpanded] = useState(false)

  const loadRules = async () => {
    try {
      const resp = await policySetsApi.listRules(policySet.id)
      setRules(resp.data.rules)
    } catch {}
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
  const [savingOrder, setSavingOrder] = useState(false)

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
      await policySetsApi.reorder(policySet.id, rules.map((r) => r.id))
    } catch (e: unknown) {
      alert((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to save order")
    } finally {
      setSavingOrder(false)
    }
  }

  useEffect(() => { if (expanded) loadRules() }, [expanded]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Accordion expanded={expanded} onChange={() => setExpanded(!expanded)} sx={{ mb: 1 }}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
          <Typography variant="h6">{policySet.name}</Typography>
          <Chip label={`${rules.length} rules`} size="small" />
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
          <Typography variant="subtitle2">Rules (drag to reorder)</Typography>
          {rules.length > 1 && (
            <Button size="small" variant="outlined" disabled={savingOrder} onClick={saveOrder}>
              {savingOrder ? "Saving..." : "Save Order"}
            </Button>
          )}
        </Box>
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
          <SortableContext items={rules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
            <List>
              {rules.map((rule) => (
                <SortableRuleItem key={rule.id} rule={rule} />
              ))}
            </List>
          </SortableContext>
        </DndContext>
        {rules.length === 0 && <Typography color="textSecondary">No rules in this policy set</Typography>}
      </AccordionDetails>
    </Accordion>
  )
}

function PolicySetDialog({ open, onClose, editingSet }: { open: boolean; onClose: () => void; editingSet: FirewallPolicySet | null }) {
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (editingSet) { setName(editingSet.name); setDescription(editingSet.description) }
    else { setName(""); setDescription("") }
  }, [editingSet, open])

  const handleSubmit = async () => {
    try {
      if (editingSet) { await policySetsApi.update(editingSet.id, { name, description }) }
      else { await policySetsApi.create({ name, description }) }
      onClose()
    } catch (e: unknown) { setError((e as { response?: { data?: { error?: { message?: string } } } })?.response?.data?.error?.message || "Failed to save") }
  }

  return (
    <Dialog open={open} onClose={onClose} fullWidth>
      <DialogTitle>{editingSet ? "Edit Policy Set" : "Create Policy Set"}</DialogTitle>
      <DialogContent>
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} fullWidth sx={{ mt: 1 }} required />
        <TextField label="Description" value={description} onChange={(e) => setDescription(e.target.value)} fullWidth sx={{ mt: 2 }} />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={!name}>{editingSet ? "Update" : "Create"}</Button>
      </DialogActions>
    </Dialog>
  )
}

function SortableRuleItem({ rule }: { rule: FirewallRule }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: rule.id })
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
        primary={rule.name}
        secondary={`${rule.action} ${rule.direction} ${rule.protocol} ${rule.src_cidr || "any"} → ${rule.dst_port_start || "any"}`}
      />
      <ListItemSecondaryAction>
        <Chip label={rule.action} size="small" color={rule.action === "allow" ? "success" : "default"} />
      </ListItemSecondaryAction>
    </ListItem>
  )
}
