import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, FancyBboxPatch
import matplotlib.patches as mpatches

# Create figure and ax
fig, ax = plt.subplots(1, 1, figsize=(14, 10))

# Main package box
ax.add_patch(FancyBboxPatch((0, 0), 12, 9, boxstyle="round,pad=0.2", facecolor='whitesmoke', alpha=0.7, linewidth=2))
ax.text(6, 8.7, 'Homomorphic Cryptography Package', ha='center', va='center', fontsize=18, fontweight='bold')

# Define colors
utils_color = 'lightblue'
schemes_color = 'thistle'
zkp_color = 'lightcoral'
blockchain_color = 'lightgoldenrodyellow'
demos_color = 'lightgreen'

# Create boxes for each module
utils = FancyBboxPatch((0.5, 7), 2, 1, boxstyle="round,pad=0.1", facecolor=utils_color, alpha=0.7)
schemes = FancyBboxPatch((3, 7), 2, 1, boxstyle="round,pad=0.1", facecolor=schemes_color, alpha=0.7)
zkp = FancyBboxPatch((5.5, 7), 2, 1, boxstyle="round,pad=0.1", facecolor=zkp_color, alpha=0.7)
blockchain = FancyBboxPatch((8, 7), 3, 1, boxstyle="round,pad=0.1", facecolor=blockchain_color, alpha=0.7)
demos = FancyBboxPatch((5, 4.5), 3, 1, boxstyle="round,pad=0.1", facecolor=demos_color, alpha=0.7)
main = FancyBboxPatch((5.5, 6), 1, 0.3, boxstyle="round,pad=0.1", facecolor='wheat', alpha=0.7)

# Add boxes
ax.add_patch(utils)
ax.add_patch(schemes)
ax.add_patch(zkp)
ax.add_patch(blockchain)
ax.add_patch(demos)
ax.add_patch(main)

# Add text labels
ax.text(1.5, 7.5, 'utils', ha='center', va='center', fontsize=14)
ax.text(4, 7.5, 'schemes', ha='center', va='center', fontsize=14)
ax.text(6.5, 7.5, 'zkp', ha='center', va='center', fontsize=14)
ax.text(9.5, 7.5, 'blockchain', ha='center', va='center', fontsize=14)
ax.text(6.5, 5, 'demos', ha='center', va='center', fontsize=14)
ax.text(6, 6.15, 'main.py', ha='center', va='center', fontsize=12)

# Add files for each module
utils_files = ['primes.py', 'math_helpers.py']
schemes_files = ['paillier.py', 'pedersen_elgamal.py', 'ring_pedersen_elgamal.py']
zkp_files = ['base.py', 'zk_pedersen_elgamal.py']
blockchain_files = ['base.py', 'state_manager.py', 'zk_integration.py']
demos_files = ['paillier_demo.py', 'pedersen_elgamal_demo.py', 'ring_demo.py', 'zk_demo.py', 'blockchain_demo.py']

def add_files(files, x_start, y_start, color, small=False):
    for i, file in enumerate(files):
        if small:
            y = y_start - 0.3 * (i + 1)
            file_box = Rectangle((x_start, y), 1.8, 0.2, facecolor=color, alpha=0.4)
            ax.add_patch(file_box)
            ax.text(x_start + 0.9, y + 0.1, file, ha='center', va='center', fontsize=8)
        else:
            y = y_start - 0.4 * (i + 1)
            file_box = Rectangle((x_start, y), 1.8, 0.3, facecolor=color, alpha=0.4)
            ax.add_patch(file_box)
            ax.text(x_start + 0.9, y + 0.15, file, ha='center', va='center', fontsize=9)

# Add files
add_files(utils_files, 0.6, 6.8, utils_color)
add_files(schemes_files, 3.1, 6.8, schemes_color)
add_files(zkp_files, 5.6, 6.8, zkp_color)
add_files(blockchain_files, 8.6, 6.8, blockchain_color)
add_files(demos_files, 5.1, 4.3, demos_color, True)

# Add arrows from main.py to modules
ax.annotate('', xy=(1.5, 7), xytext=(6, 6),
            arrowprops=dict(arrowstyle='->', color='black', alpha=0.6))
ax.annotate('', xy=(4, 7), xytext=(6, 6),
            arrowprops=dict(arrowstyle='->', color='black', alpha=0.6))
ax.annotate('', xy=(6.5, 7), xytext=(6, 6),
            arrowprops=dict(arrowstyle='->', color='black', alpha=0.6))
ax.annotate('', xy=(9.5, 7), xytext=(6, 6),
            arrowprops=dict(arrowstyle='->', color='black', alpha=0.6))
ax.annotate('', xy=(6.5, 5.5), xytext=(6, 6),
            arrowprops=dict(arrowstyle='->', color='black', alpha=0.6))

# Add arrows between modules
ax.annotate('', xy=(3, 7.5), xytext=(2.5, 7.5),
            arrowprops=dict(arrowstyle='->', color='black', alpha=0.6))
ax.annotate('', xy=(5.5, 7.5), xytext=(5, 7.5),
            arrowprops=dict(arrowstyle='->', color='black', alpha=0.6))
ax.annotate('', xy=(8, 7.5), xytext=(7.5, 7.5),
            arrowprops=dict(arrowstyle='->', color='black', alpha=0.6))
ax.annotate('', xy=(9.5, 6.8), xytext=(6.5, 6),
            arrowprops=dict(arrowstyle='->', color='black', alpha=0.6, linestyle='dashed'))

# Create legend
utils_patch = mpatches.Patch(color=utils_color, alpha=0.7, label='Utilities')
schemes_patch = mpatches.Patch(color=schemes_color, alpha=0.7, label='Encryption Schemes')
zkp_patch = mpatches.Patch(color=zkp_color, alpha=0.7, label='Zero-Knowledge Proofs')
blockchain_patch = mpatches.Patch(color=blockchain_color, alpha=0.7, label='Blockchain State Management')
demos_patch = mpatches.Patch(color=demos_color, alpha=0.7, label='Demo Applications')
main_patch = mpatches.Patch(color='wheat', alpha=0.7, label='Main Entry Point')

plt.legend(handles=[utils_patch, schemes_patch, zkp_patch, blockchain_patch, demos_patch, main_patch], 
           loc='upper center', bbox_to_anchor=(0.5, -0.03), ncol=3, frameon=False)

# Remove axis
ax.set_xlim(-0.5, 12.5)
ax.set_ylim(-0.5, 9.5)
ax.set_aspect('equal')
ax.axis('off')

plt.title('Homomorphic Cryptography Package Architecture', fontsize=16, pad=15)
plt.tight_layout()
plt.savefig('/tmp/outputs/fixed_architecture_diagram.png', dpi=150, bbox_inches='tight')
plt.close()

# Create a before/after comparison
fig3, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 9))

# BEFORE
ax1.add_patch(Rectangle((0, 0), 10, 7, facecolor='whitesmoke', alpha=0.3))
ax1.text(5, 6.5, 'BEFORE', ha='center', va='center', fontsize=16, fontweight='bold')

original_files = [
    'paillier.py', 'pedersen elgamal.py', 'primes.py', 
    'ring pedersen elgamal.py', 'zk pedersen elgamal.py', 'zkp.py'
]

for i, file in enumerate(original_files):
    y = 5.5 - 0.6 * i
    file_box = Rectangle((2, y-0.2), 6, 0.4, facecolor='lightgray', alpha=0.7)
    ax1.add_patch(file_box)
    ax1.text(5, y, file, ha='center', va='center', fontsize=11)

# AFTER
ax2.add_patch(Rectangle((0, 0), 10, 7, facecolor='whitesmoke', alpha=0.3))
ax2.text(5, 6.5, 'AFTER', ha='center', va='center', fontsize=16, fontweight='bold')

module_positions = {
    'utils': (1, 5, utils_color),
    'schemes': (3, 5, schemes_color),
    'zkp': (5, 5, zkp_color),
    'blockchain': (7, 5, blockchain_color),
    'demos': (5, 3, demos_color),
    'main.py': (9, 5, 'wheat'),
}

for name, (x, y, color) in module_positions.items():
    if name == 'main.py':
        box = FancyBboxPatch((x-1, y-0.2), 2, 0.4, boxstyle="round,pad=0.2", facecolor=color, alpha=0.7)
        ax2.add_patch(box)
        ax2.text(x, y, name, ha='center', va='center', fontsize=10)
    else:
        box = FancyBboxPatch((x-1, y-0.3), 2, 0.6, boxstyle="round,pad=0.2", facecolor=color, alpha=0.7)
        ax2.add_patch(box)
        ax2.text(x, y, name, ha='center', va='center', fontsize=12)

# Add arrows for dependencies in AFTER diagram
dependencies = [
    ('main.py', 'demos'),
    ('demos', 'schemes'),
    ('demos', 'zkp'),
    ('demos', 'blockchain'),
    ('blockchain', 'zkp'),
    ('schemes', 'utils'),
    ('zkp', 'schemes'),
    ('zkp', 'utils'),
]

for source, target in dependencies:
    x1, y1 = module_positions[source][:2]
    x2, y2 = module_positions[target][:2]
    ax2.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color='darkgray', alpha=0.7))

# Remove axis from both subplots
for ax in [ax1, ax2]:
    ax.set_xlim(-0.5, 10.5)
    ax.set_ylim(-0.5, 7.5)
    ax.axis('off')

plt.suptitle('Code Organization Comparison', fontsize=18, y=0.98)
plt.tight_layout()
plt.savefig('/tmp/outputs/fixed_before_after_comparison.png', dpi=150, bbox_inches='tight')

print("Architecture diagrams generated successfully in /tmp/outputs/")
