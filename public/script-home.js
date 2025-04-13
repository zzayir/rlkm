document.addEventListener('DOMContentLoaded', function() {
    // Initialize spending chart
    const spendingCtx = document.getElementById('spendingChart').getContext('2d');
    const spendingChart = new Chart(spendingCtx, {
        type: 'bar',
        data: {
            labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            datasets: [{
                label: 'Spending',
                data: [1200, 1900, 1500, 2000, 1800, 2200],
                backgroundColor: [
                    'rgba(67, 97, 238, 0.7)',
                    'rgba(67, 97, 238, 0.7)',
                    'rgba(67, 97, 238, 0.7)',
                    'rgba(67, 97, 238, 0.7)',
                    'rgba(67, 97, 238, 0.7)',
                    'rgba(67, 97, 238, 0.7)'
                ],
                borderColor: [
                    'rgba(67, 97, 238, 1)',
                    'rgba(67, 97, 238, 1)',
                    'rgba(67, 97, 238, 1)',
                    'rgba(67, 97, 238, 1)',
                    'rgba(67, 97, 238, 1)',
                    'rgba(67, 97, 238, 1)'
                ],
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        display: true,
                        drawBorder: false
                    },
                    ticks: {
                        callback: function(value) {
                            return '₹' + value;
                        }
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });

    // Simulate loading for account cards
    const accountCards = document.querySelectorAll('.account-card');
    
    accountCards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
    });

    setTimeout(() => {
        accountCards.forEach((card, index) => {
            setTimeout(() => {
                card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });
    }, 300);

    // Add click event to quick action buttons
    const actionButtons = document.querySelectorAll('.action-btn');
    
    actionButtons.forEach(button => {
        button.addEventListener('click', function() {
            // In a real app, this would trigger the appropriate action
            alert(`Action "${this.textContent.trim()}" would be performed here.`);
        });
    });

    // Add hover effect to transactions
    const transactions = document.querySelectorAll('.transaction');
    
    transactions.forEach(transaction => {
        transaction.addEventListener('mouseenter', function() {
            this.style.transform = 'translateX(5px)';
            this.style.transition = 'transform 0.2s ease';
        });
        
        transaction.addEventListener('mouseleave', function() {
            this.style.transform = 'translateX(0)';
        });
    });

    // Simulate notification
    setTimeout(() => {
        createNotification('New feature available', 'You can now set up recurring payments in the Payments section.');
    }, 2000);

    function createNotification(title, message) {
        const notification = document.createElement('div');
        notification.className = 'notification';
        notification.innerHTML = `
            <div class="notification-icon">
                <i class="fas fa-bell"></i>
            </div>
            <div class="notification-content">
                <h4>${title}</h4>
                <p>${message}</p>
            </div>
            <button class="notification-close">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.right = '20px';
            notification.style.opacity = '1';
        }, 100);
        
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.addEventListener('click', function() {
            notification.style.right = '-400px';
            notification.style.opacity = '0';
            setTimeout(() => {
                notification.remove();
            }, 300);
        });
        
        // Auto-close after 5 seconds
        setTimeout(() => {
            notification.style.right = '-400px';
            notification.style.opacity = '0';
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 5000);
    }
});

// Add notification styles dynamically
const notificationStyles = document.createElement('style');
notificationStyles.textContent = `
    .notification {
        position: fixed;
        top: 90px;
        right: -400px;
        width: 350px;
        padding: 15px;
        background-color: #fff;
        border-radius: 8px;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        display: flex;
        align-items: center;
        z-index: 1000;
        opacity: 0;
        transition: all 0.3s ease;
    }
    
    .notification-icon {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        background-color: rgba(67, 97, 238, 0.1);
        display: flex;
        align-items: center;
        justify-content: center;
        margin-right: 15px;
        color: var(--primary-color);
        flex-shrink: 0;
    }
    
    .notification-content h4 {
        font-size: 0.95rem;
        margin-bottom: 5px;
        color: var(--dark-color);
    }
    
    .notification-content p {
        font-size: 0.85rem;
        color: var(--gray-color);
        margin-bottom: 0;
    }
    
    .notification-close {
        background: none;
        border: none;
        color: var(--gray-color);
        cursor: pointer;
        margin-left: auto;
        padding: 0;
        flex-shrink: 0;
    }
`;
document.head.appendChild(notificationStyles);

// Add this JavaScript to handle dropdown toggle
function toggleDropdown() {
    const dropdown = document.getElementById('profileDropdown');
    dropdown.classList.toggle('show');
}

// Close the dropdown if clicked outside
window.onclick = function(event) {
    if (!event.target.matches('.user-profile') && !event.target.closest('.user-profile')) {
        const dropdowns = document.getElementsByClassName('profile-dropdown');
        for (let i = 0; i < dropdowns.length; i++) {
            const openDropdown = dropdowns[i];
            if (openDropdown.classList.contains('show')) {
                openDropdown.classList.remove('show');
            }
        }
    }
}

function logout() {
    window.location.href = "login.html";}