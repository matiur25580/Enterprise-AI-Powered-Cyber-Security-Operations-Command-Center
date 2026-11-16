import type { IncidentStatus } from "@soc/contracts";

const transitions: Record<IncidentStatus, readonly IncidentStatus[]> = {
  open: ["acknowledged", "investigating"],
  acknowledged: ["investigating", "contained"],
  investigating: ["contained", "resolved"],
  contained: ["investigating", "resolved"],
  resolved: ["reopened"],
  reopened: ["acknowledged", "investigating"],
};

export function canTransitionIncident(from: IncidentStatus, to: IncidentStatus): boolean {
  return transitions[from].includes(to);
}
