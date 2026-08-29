// RFC 6962 Merkle tree, byte-for-byte: leaf = SHA256(0x00‖data),
// node = SHA256(0x01‖L‖R), unbalanced split at the largest power of two
// strictly less than n (§2.1). Domain-separation prefixes defeat leaf/node
// second-preimage confusion. Verification algorithms follow RFC 9162
// §2.1.3.2 / §2.1.4.2 exactly.
import { createHash } from 'node:crypto';

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function sha256(...parts: Buffer[]): Buffer {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

export function leafHash(data: Buffer): Buffer {
  return sha256(LEAF_PREFIX, data);
}

export function nodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256(NODE_PREFIX, left, right);
}

/** Largest power of two strictly less than n (n >= 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH(D[n]) over raw leaf data. Empty tree hashes to SHA256(""). */
export function merkleRoot(leaves: readonly Buffer[]): Buffer {
  const n = leaves.length;
  if (n === 0) return sha256();
  if (n === 1) return leafHash(leaves[0]!);
  const k = split(n);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

/**
 * Incremental RFC 6962 Merkle tree.
 * Maintains the O(log N) right-hand frontier of perfect binary subtrees.
 * Appending is O(1) amortized, and root computation is O(log N).
 */
export class IncrementalMerkleTree {
  private count = 0;
  private frontier: (Buffer | undefined)[] = [];

  constructor() {}

  get size(): number {
    return this.count;
  }

  append(leafData: Buffer): void {
    let current = leafHash(leafData);
    let index = 0;
    let c = this.count;

    while (c % 2 === 1) {
      const left = this.frontier[index];
      if (left !== undefined) {
        current = nodeHash(left, current);
        this.frontier[index] = undefined;
      }
      c = Math.floor(c / 2);
      index++;
    }

    this.frontier[index] = current;
    this.count++;
  }

  root(): Buffer {
    if (this.count === 0) return sha256();

    const activeRoots: Buffer[] = [];
    for (let i = 0; i < this.frontier.length; i++) {
      const f = this.frontier[i];
      if (f !== undefined) {
        activeRoots.push(f);
      }
    }

    if (activeRoots.length === 0) return sha256();
    if (activeRoots.length === 1) return activeRoots[0]!;

    let r = activeRoots[0]!;
    for (let i = 1; i < activeRoots.length; i++) {
      r = nodeHash(activeRoots[i]!, r);
    }
    return r;
  }
}

/** RFC 6962 §2.1.1 PATH(m, D[n]) — audit path for leaf m, bottom-up. */
export function inclusionProof(m: number, leaves: readonly Buffer[]): Buffer[] {
  const n = leaves.length;
  if (m >= n || m < 0) throw new Error(`leaf index ${m} out of range [0, ${n})`);
  if (n === 1) return [];
  const k = split(n);
  if (m < k) {
    return [...inclusionProof(m, leaves.slice(0, k)), merkleRoot(leaves.slice(k))];
  }
  return [...inclusionProof(m - k, leaves.slice(k)), merkleRoot(leaves.slice(0, k))];
}

/** RFC 6962 §2.1.2 PROOF(m, D[n]) — consistency between sizes m and n. */
export function consistencyProof(m: number, leaves: readonly Buffer[]): Buffer[] {
  const n = leaves.length;
  if (m < 1 || m > n) throw new Error(`old size ${m} out of range [1, ${n}]`);
  if (m === n) return [];
  return subProof(m, leaves, true);
}

function subProof(m: number, leaves: readonly Buffer[], isCompleteSubtree: boolean): Buffer[] {
  const n = leaves.length;
  if (m === n) {
    return isCompleteSubtree ? [] : [merkleRoot(leaves)];
  }
  const k = split(n);
  if (m <= k) {
    return [...subProof(m, leaves.slice(0, k), isCompleteSubtree), merkleRoot(leaves.slice(k))];
  }
  return [...subProof(m - k, leaves.slice(k), false), merkleRoot(leaves.slice(0, k))];
}

/** RFC 9162 §2.1.3.2 — verify an inclusion proof (path is bottom-up). */
export function verifyInclusion(
  leafIndex: number,
  treeSize: number,
  leaf: Buffer,
  path: readonly Buffer[],
  root: Buffer,
): boolean {
  const r = rootFromInclusion(leafIndex, treeSize, leaf, path);
  return r !== undefined && r.equals(root);
}

/** Compute the root implied by an inclusion proof; undefined if malformed. */
export function rootFromInclusion(
  leafIndex: number,
  treeSize: number,
  leaf: Buffer,
  path: readonly Buffer[],
): Buffer | undefined {
  if (leafIndex >= treeSize || leafIndex < 0) return undefined;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return undefined;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn !== 0 && fn % 2 === 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 ? r : undefined;
}

/** RFC 9162 §2.1.4.2 — verify a consistency proof between two roots. */
export function verifyConsistency(
  firstSize: number,
  secondSize: number,
  firstRoot: Buffer,
  secondRoot: Buffer,
  proof: readonly Buffer[],
): boolean {
  if (firstSize === secondSize) {
    return proof.length === 0 && firstRoot.equals(secondRoot);
  }
  if (firstSize < 1 || firstSize > secondSize) return false;
  let path = proof;
  if (Number.isInteger(Math.log2(firstSize))) {
    path = [firstRoot, ...proof];
  }
  if (path.length === 0) return false;
  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = path[0]!;
  let sr = path[0]!;
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if (fn % 2 === 0) {
        while (fn !== 0 && fn % 2 === 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && fr.equals(firstRoot) && sr.equals(secondRoot);
}
