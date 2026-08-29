// Tests for IncrementalMerkleTree correctness against canonical RFC 6962 merkleRoot
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { IncrementalMerkleTree, merkleRoot } from '../src/merkle.ts';

test('IncrementalMerkleTree matches merkleRoot on sizes 0 to 128', () => {
  const tree = new IncrementalMerkleTree();
  const leaves: Buffer[] = [];

  assert.equal(tree.root().toString('hex'), merkleRoot(leaves).toString('hex'));

  for (let i = 1; i <= 128; i++) {
    const leaf = randomBytes(32);
    leaves.push(leaf);
    tree.append(leaf);

    const incrementalRoot = tree.root().toString('hex');
    const batchRoot = merkleRoot(leaves).toString('hex');
    assert.equal(
      incrementalRoot,
      batchRoot,
      `Incremental root mismatch at size ${i}: ${incrementalRoot} vs ${batchRoot}`,
    );
  }
});

test('IncrementalMerkleTree size property tracks correctly', () => {
  const tree = new IncrementalMerkleTree();
  assert.equal(tree.size, 0);

  for (let i = 1; i <= 10; i++) {
    tree.append(Buffer.from(`leaf-${i}`));
    assert.equal(tree.size, i);
  }
});
