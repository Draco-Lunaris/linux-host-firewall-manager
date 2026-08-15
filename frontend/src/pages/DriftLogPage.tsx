import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  type SelectChangeEvent,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material'
import { History as HistoryIcon, Refresh as RefreshIcon } from '@mui/icons-material'
import { driftApi, type DriftSnapshot } from '../api/client'

function fmtTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function shortHash(h: string): string {
  return h.length > 12 ? `${h.slice(0, 8)}…${h.slice(-4)}` : h
}

function eventChip(source: string) {
  if (source === 'check_in_mismatch') {
    return <Chip label="Drifted" color="warning" size="small" />
  }
  if (source === 'agent_report') {
    return <Chip label="Applied" color="info" size="small" variant="outlined" />
  }
  return <Chip label={source} size="small" variant="outlined" />
}

export default function DriftLogPage() {
  const [snapshots, setSnapshots] = useState<DriftSnapshot[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [hostFilter, setHostFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [limit, setLimit] = useState(200)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params: { host_id?: string; limit?: number } = { limit }
      if (hostFilter.trim()) params.host_id = hostFilter.trim()
      const res = await driftApi.list(params)
      setSnapshots(res.data)
    } catch {
      setError('Failed to load drift history')
    } finally {
      setLoading(false)
    }
  }, [hostFilter, limit])

  useEffect(() => {
    void load()
  }, [load])

  const filtered =
    sourceFilter === 'all'
      ? snapshots
      : snapshots.filter((s) => s.source === sourceFilter)

  return (
    <Container maxWidth="xl" sx={{ mt: 3, mb: 6 }}>
      <Toolbar disableGutters sx={{ mb: 3 }}>
        <HistoryIcon sx={{ mr: 1, color: 'primary.main' }} />
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>
          Drift Log
        </Typography>
        <Tooltip title="Refresh">
          <span>
            <IconButton onClick={load} disabled={loading}>
              {loading ? <CircularProgress size={20} /> : <RefreshIcon />}
            </IconButton>
          </span>
        </Tooltip>
      </Toolbar>

      <Alert severity="info" sx={{ mb: 3 }}>
        Audit history of firewall-rule drift across the fleet. <strong>Drifted</strong> rows mark
        check-ins where a host&apos;s live rules diverged from its assigned policy;{' '}
        <strong>Applied</strong> rows mark rulesets the agent applied (often the self-correction
        following a drift). Rows are retained indefinitely for investigating unauthorized or
        out-of-band firewall changes.
      </Alert>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Box display="flex" gap={2} sx={{ mb: 3 }} flexWrap="wrap">
        <TextField
          size="small"
          label="Filter by Host ID"
          value={hostFilter}
          onChange={(e) => setHostFilter(e.target.value)}
          placeholder="UUID…"
          sx={{ minWidth: 260 }}
        />
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Event</InputLabel>
          <Select
            label="Event"
            value={sourceFilter}
            onChange={(e: SelectChangeEvent) => setSourceFilter(e.target.value)}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="check_in_mismatch">Drifted</MenuItem>
            <MenuItem value="agent_report">Applied</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Limit</InputLabel>
          <Select
            label="Limit"
            value={String(limit)}
            onChange={(e: SelectChangeEvent) => setLimit(Number(e.target.value))}
          >
            <MenuItem value={100}>100</MenuItem>
            <MenuItem value={200}>200</MenuItem>
            <MenuItem value={500}>500</MenuItem>
            <MenuItem value={1000}>1000</MenuItem>
          </Select>
        </FormControl>
        <Button variant="outlined" size="small" onClick={load} disabled={loading}>
          Apply
        </Button>
      </Box>

      <Paper variant="outlined">
        {loading ? (
          <Box display="flex" justifyContent="center" py={6}>
            <CircularProgress />
          </Box>
        ) : filtered.length === 0 ? (
          <Box p={4}>
            <Alert severity="info">No drift events recorded.</Alert>
          </Box>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Host</TableCell>
                <TableCell>Event</TableCell>
                <TableCell align="right">Rules</TableCell>
                <TableCell>Rules Hash</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filtered.map((s) => (
                <TableRow key={s.id} hover>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 12 }}>
                      {fmtTime(s.captured_at)}
                    </Typography>
                  </TableCell>
                  <TableCell>{s.fqdn}</TableCell>
                  <TableCell>{eventChip(s.source)}</TableCell>
                  <TableCell align="right">{s.rule_count}</TableCell>
                  <TableCell>
                    <Tooltip title={s.snapshot_hash}>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                        {shortHash(s.snapshot_hash)}
                      </Typography>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Paper>
    </Container>
  )
}